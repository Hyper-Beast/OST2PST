"""M7 public CLI contract using synthetic stores, never a private mailbox."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--ost2pst', required=True)
parser.add_argument('--ostinfo', required=True)
parser.add_argument('--workdir', default='.')
parser.add_argument('--fixture-builder')
args, unittest_args = parser.parse_known_args()
OST2PST = str(Path(args.ost2pst).resolve())
OSTINFO = str(Path(args.ostinfo).resolve())
BUILDER = str(Path(args.fixture_builder).resolve()) if args.fixture_builder else None
WORK = Path(args.workdir).resolve()
WORK.mkdir(parents=True, exist_ok=True)


class CliContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='m7-cli-', dir=WORK)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source with spaces.pst'
        result = self.run_cli('--empty', self.source)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.original = self.source.read_bytes()

    def run_cli(self, *arguments, reader=False):
        return subprocess.run([OSTINFO if reader else OST2PST, *map(str, arguments)],
                              cwd=self.root, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, errors='replace', timeout=10)

    def expect(self, result, code, *texts):
        self.assertEqual(result.returncode, code, result.stdout)
        for text in texts:
            self.assertIn(text, result.stdout)

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob('*')}

    def test_read_only_modes_create_nothing(self):
        output = self.root / 'existing.pst'
        output.write_bytes(b'EXISTING USER DATA')
        before = self.snapshot()
        self.expect(self.run_cli('--verify', self.source), 0, 'VERIFY RESULT: clean')
        # A blank store has no initialized Name-to-ID map; full-mode planning refuses it too.
        self.expect(self.run_cli('--dry-run', self.source), 3, 'mailbox.name_map')
        self.assertEqual(self.snapshot(), before)
        if BUILDER is None:
            self.skipTest('positive planning requires the synthetic content builder')
        generated = subprocess.run([BUILDER, str(self.source)], capture_output=True,
                                   text=True, cwd=self.root, timeout=10)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        before = self.snapshot()
        self.expect(self.run_cli('--dry-run', self.source), 0, 'DRY-RUN RESULT: planned')
        self.expect(self.run_cli('--verify', self.source), 0, 'VERIFY RESULT: clean')
        self.expect(self.run_cli('--dry-run', self.source), 0, 'normal=1')
        self.expect(self.run_cli('--dry-run', self.source, output), 0, 'not checked')
        self.assertEqual(self.snapshot(), before)
        output.unlink()
        before = self.snapshot()
        self.expect(self.run_cli('--dry-run', self.source, output), 0)
        self.assertEqual(self.snapshot(), before)
        self.expect(self.run_cli('--dry-run', self.source, self.root/'absent'/'out.pst'), 0)
        self.assertEqual(self.snapshot(), before)

    def test_unicode_paths_are_readable_and_reported(self):
        if BUILDER is None:
            self.skipTest('planning requires the synthetic content builder')
        source = self.root/'邮件源.pst'
        made = subprocess.run([BUILDER, str(source)], capture_output=True, timeout=10)
        self.assertEqual(made.returncode, 0)
        destination = self.root/'未创建的目录'/'结果.pst'
        before = self.snapshot()
        run = subprocess.run([OST2PST, '--dry-run', str(source), str(destination)],
                             cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn(str(destination), run.stdout.decode('utf-8'))
        self.assertEqual(self.snapshot(), before)

    def test_platform_refusal_names_actual_field_and_byte(self):
        for offset, field in ((14, 'bPlatformCreate'), (15, 'bPlatformAccess')):
            data = bytearray(self.original)
            data[offset] = 0xFE
            self.source.write_bytes(data)
            for reader, mode in ((False, '--verify'), (True, '--probe')):
                self.expect(self.run_cli(mode, self.source, reader=reader), 2,
                            f'HEADER.{field}', f'offset=0x{offset:08X}', 'value=0xFE')

    def test_short_ansi_and_wip_refuse_exact_version(self):
        # [MS-PST] 2.2.2.1: version is in the shared first 12 bytes, before layout differs.
        for version in (14, 15, 37):
            with self.subTest(version=version):
                value = bytearray(self.original[:12])
                struct.pack_into('<H', value, 10, version)
                self.source.write_bytes(value)
                for arguments, reader in [(['--verify'], False), (['--probe'], True)]:
                    self.expect(self.run_cli(*arguments, self.source, reader=reader), 2,
                                'HEADER.wVer', f'value=0x{version:X}')
                target = self.root / 'absent.pst'
                self.expect(self.run_cli(self.source, target), 2, 'HEADER.wVer')
                self.assertFalse(target.exists())
                self.assertFalse(list(self.root.glob('*.ost2pst*')))

    def test_encoding_policy_names_exact_byte(self):
        # [MS-PST] 2.2.2.1 HEADER.bCryptMethod @ 0x201.
        for value in (1, 2, 0x10, 0xFF):
            with self.subTest(value=value):
                data = bytearray(self.original)
                data[0x201] = value
                self.source.write_bytes(data)
                self.expect(self.run_cli('--verify', self.source), 2,
                            'HEADER.bCryptMethod', f'value=0x{value:X}')

    def test_truncation_does_not_overwrite(self):
        output = self.root / 'protected.pst'
        output.write_bytes(b'KEEP')
        self.source.write_bytes(self.original[:-1])
        before = self.snapshot()
        for options in (['--verify'], ['--dry-run'], ['--folder', '0x8022', '--force']):
            argv = [*options, self.source]
            if '--folder' in options:
                argv.append(output)
            self.expect(self.run_cli(*argv), 3, 'ROOT.ibFileEof', 'truncated')
        self.expect(self.run_cli(self.source, self.root/'new.pst'), 3, 'ROOT.ibFileEof')
        self.assertEqual(self.snapshot(), before)

    def test_bad_header_crc_reports_corruption(self):
        data = bytearray(self.original)
        data[4] ^= 1
        self.source.write_bytes(data)
        self.expect(self.run_cli('--verify', self.source), 3, 'HEADER.dwCRCPartial')
        self.expect(self.run_cli('--probe', self.source, reader=True), 3, 'HEADER.dwCRCPartial')

    def test_bad_bbt_does_not_masquerade_as_unsupported_format(self):
        data = bytearray(self.original)
        # [MS-PST] 2.2.2.5: ROOT BREFBBT.ib is @ 0x0F0 in the Unicode header.
        root_ib = struct.unpack_from('<Q', data, 0x0F0)[0]
        data[root_ib] ^= 1
        self.source.write_bytes(data)
        output = self.root/'out.pst'
        before = self.snapshot()
        for reader, argv in ((False, ['--verify', self.source]),
                             (False, ['--folder', '0x8022', self.source, output]),
                             (False, [self.source, output]),
                             (True, ['--probe', self.source]),
                             (True, ['--ltp', self.source]),
                             (True, ['--inventory', self.source])):
            self.expect(self.run_cli(*argv, reader=reader), 3, 'BTPAGE.pageTrailer')
        self.assertEqual(self.snapshot(), before)

    def test_full_manifest_failure_is_input_error_without_staging(self):
        before = self.snapshot()
        self.expect(self.run_cli(self.source, self.root/'out.pst'), 3, 'mailbox.name_map')
        self.assertEqual(self.snapshot(), before)

    def test_read_only_flag_conflicts_are_usage_errors(self):
        for options in (['--verify', '--dry-run'], ['--verify', '--empty'],
                        ['--dry-run', '--resume'], ['--dry-run', '--force'],
                        ['--verify', '--folder', '0x8022'],
                        ['--dry-run', '--max-messages', '8']):
            with self.subTest(options=options):
                before = self.snapshot()
                self.expect(self.run_cli(*options, self.source), 1)
                self.assertEqual(self.snapshot(), before)
        self.expect(self.run_cli('--verify', self.source, 'extra.pst'), 1)
        self.expect(self.run_cli('--empty', self.source, 'extra.pst'), 1)

    def test_numeric_options_require_entire_unsigned_token(self):
        output = self.root / 'should-not-exist.pst'
        for value in ('-1', '+1', '8junk', '18446744073709551616',
                      ' 1', '\t1', '\r1', '\n1', '\v1', '\f1'):
            with self.subTest(value=value):
                before = self.snapshot()
                self.expect(self.run_cli('--folder', '0x8022', '--max-messages', value,
                                         self.source, output), 1)
                self.expect(self.run_cli('--folder', '0x8022junk', self.source, output), 1)
                self.expect(self.run_cli('--inventory', '--max-messages', value,
                                         self.source, reader=True), 1)
                self.assertEqual(self.snapshot(), before)

    def test_missing_input_is_io(self):
        for mode in ('--dry-run', '--verify'):
            self.expect(self.run_cli(mode, 'absent.ost'), 1, 'FileReader.open')


if __name__ == '__main__':
    unittest.main(argv=[__file__, *unittest_args])
