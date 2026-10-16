import copy
import ctypes
import importlib.util
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
import zlib

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('verify_full', root / 'scripts/verify_full.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
api_path = root / 'tests/tools/libpff_fai_compare.py'
api_spec = importlib.util.spec_from_file_location('libpff_compare', api_path)
api_probe = importlib.util.module_from_spec(api_spec)
api_spec.loader.exec_module(api_probe)


class FullGateTest(unittest.TestCase):
    def setUp(self):
        populations = dict(embedded=0, recipients=1, attachments=1, opaque_objects=0, attachment_bytes=7)
        self.report = dict(schema=1, status='complete', exit_code=0, internal_verification='passed',
                           source_sha256='identity', pst_bytes=42, skipped_corrupt=0,
                           skipped_unsupported=0, failed=0, unknown_source_populations=0,
                           unknown_read_state=0, source=populations, committed=populations,
                           output_verified=populations, items=2, terminal=2, converted_fai=1,
                           converted_normal=1, coverage={'content': 3}, folders=1)
        self.records = [dict(schema=1, kind='item', source_nid=36, output_nid=68,
                             source_parent=34, output_parent=66,
                             associated=False, status='converted', source_complete=True,
                             source=populations, committed=populations),
                        dict(schema=1, kind='item', source_nid=40, output_nid=72,
                             source_parent=34, output_parent=66,
                             associated=True, status='converted', source_complete=True,
                             source={k: 0 for k in populations}, committed={k: 0 for k in populations})]
        self.records += [dict(schema=1, kind='coverage', source_nid=nid, source_parent=34,
                             output_nid=nid + 32, status='content') for nid in (34, 36, 40)]

    def check_gate(self):
        return gate.validate_report(self.report, self.records, 'identity', 42)

    def test_complete(self):
        self.assertEqual(len(self.check_gate()), 2)

    def test_incomplete(self):
        for key in ('skipped_corrupt', 'skipped_unsupported', 'failed', 'unknown_source_populations', 'unknown_read_state'):
            original = self.report[key]
            self.report[key] = 1
            with self.subTest(key=key), self.assertRaises(gate.GateFailure):
                self.check_gate()
            self.report[key] = original

    def test_missing_fai(self):
        del self.records[1]
        with self.assertRaises(gate.GateFailure):
            self.check_gate()

    def test_duplicate_and_unreadable(self):
        self.records[1]['output_nid'] = self.records[0]['output_nid']
        with self.assertRaises(gate.GateFailure):
            self.check_gate()
        self.records[1]['output_nid'] = 72
        self.records[1]['source_complete'] = False
        with self.assertRaises(gate.GateFailure):
            self.check_gate()

    def test_inconsistent_coverage_and_counts(self):
        self.report['folders'] = 2
        with self.assertRaises(gate.GateFailure):
            self.check_gate()
        self.report['folders'] = 1
        self.report['source'] = copy.deepcopy(self.report['source'])
        self.report['source']['attachment_bytes'] = 8
        with self.assertRaises(gate.GateFailure):
            self.check_gate()

    def test_mapping_and_parent(self):
        for key, value in (('source_parent', 999), ('output_parent', 999), ('associated', True)):
            records = copy.deepcopy(self.records)
            self.records[0][key] = value
            with self.subTest(key=key), self.assertRaises(gate.GateFailure):
                self.check_gate()
            self.records = records
        self.records[-1]['output_nid'] = 999
        with self.assertRaises(gate.GateFailure):
            self.check_gate()

    def test_foreign_bytes_and_missing_verdict(self):
        self.report['pst_bytes'] = 43
        with self.assertRaises(gate.GateFailure):
            self.check_gate()
        self.report['pst_bytes'] = 42
        del self.report['internal_verification']
        with self.assertRaises(gate.GateFailure):
            self.check_gate()

    def test_performance_limits(self):
        gate.validate_metrics(dict(wall_seconds=899, peak_working_set=999999999))
        for values in ({}, dict(wall_seconds=900, peak_working_set=1),
                       dict(wall_seconds=1, peak_working_set=1000000000)):
            with self.subTest(values=values), self.assertRaises(gate.GateFailure):
                gate.validate_metrics(values)

    def test_missing_independent_coverage(self):
        complete = dict(result='PASS', items=2, fai_items=1, folder_tables=2)
        gate.validate_independent(complete, self.report)
        for key, value in (('result', 'FAIL'), ('items', 1), ('fai_items', 0), ('folder_tables', 1)):
            incomplete = dict(complete)
            incomplete[key] = value
            with self.subTest(key=key), self.assertRaises(gate.GateFailure):
                gate.validate_independent(incomplete, self.report)

    def test_named_identity_keeps_counted_string_bytes(self):
        class NamedApi(api_probe.Pff):
            def __init__(self, name):
                self.p = ctypes.c_void_p
                self.name = name

            def scalar(self, function, obj, kind=None):
                return ord('s') if function.endswith('_type') else len(self.name)

            def call(self, function, *args, **kwargs):
                if function == 'name_to_id_map_entry_get_guid':
                    ctypes.memmove(args[1], bytes(16), 16)
                elif function == 'name_to_id_map_entry_get_utf8_string':
                    ctypes.memmove(args[1], self.name, len(self.name))
                return 1

        ordinary = NamedApi(b'name\0').identity(None, 0x8000, 3)
        trailing_zero = NamedApi(b'name\0\0').identity(None, 0x8001, 3)
        self.assertNotEqual(ordinary, trailing_zero)
        self.assertEqual(ordinary, NamedApi(b'name\0').identity(None, 0x8002, 3))

    def test_actual_missing_tool_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'missing.txt'
            with self.assertRaisesRegex(gate.GateFailure, 'NOT VERIFIED'):
                gate.run([str(Path(directory) / 'does-not-exist.exe')], log)
            log = Path(directory) / 'failure.txt'
            with self.assertRaisesRegex(gate.GateFailure, 'exited 3'):
                gate.run([sys.executable, '-c', 'print("injected failure"); raise SystemExit(3)'], log)
            self.assertIn('injected failure', log.read_text())

    def test_fixed_map_trailer_and_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'maps.pst'
            # Synthetic 129-region file crosses the independently observed FMap
            # boundary 0x1F04800; payload storage is not part of this gate test.
            size = 0x4400 + 129 * 253952
            header = bytearray(512)
            header[:4], header[8:10] = b'!BDN', b'SM'
            struct.pack_into('<H', header, 10, 23)
            struct.pack_into('<Q', header, 0xB8, size)
            def page(at, typ, bits):
                buf = bytearray(512)
                buf[:496] = bits
                struct.pack_into('<BBHIQ', buf, 496, typ, typ, 0,
                                 zlib.crc32(bits, 0xFFFFFFFF) ^ 0xFFFFFFFF, at)
                return buf
            with path.open('wb') as file:
                file.write(header)
                file.truncate(size)
                for region in range(129):
                    base = 0x4400 + region * 253952
                    file.seek(base)
                    file.write(page(base, 0x84, bytes([0xFF]) * 496))
                    if region % 8 == 0:
                        file.seek(base + 512)
                        file.write(page(base + 512, 0x83, bytes([0xFF]) * 496))
            with self.assertRaisesRegex(gate.GateFailure, 'FMap trailer'):
                gate.validate_fixed_maps(path)
            fmap = 0x1F04800
            valid = page(fmap, 0x82, bytes(496))
            with path.open('r+b') as file:
                file.seek(fmap)
                file.write(valid)
            self.assertEqual(gate.validate_fixed_maps(path)['pages']['FMap'], 1)
            with path.open('r+b') as file:
                file.seek(fmap)
                damaged = bytearray(valid)
                damaged[0] = 1
                file.write(damaged)
            with self.assertRaisesRegex(gate.GateFailure, 'FMap CRC'):
                gate.validate_fixed_maps(path)
            with path.open('r+b') as file:
                file.seek(fmap)
                file.write(valid)
                amap = fmap - 1024
                bits = bytearray([0xFF] * 496)
                bits[2] = 0
                file.seek(amap)
                file.write(page(amap, 0x84, bits))
            with self.assertRaisesRegex(gate.GateFailure, 'FMap page is unallocated'):
                gate.validate_fixed_maps(path)


if __name__ == '__main__':
    unittest.main()
