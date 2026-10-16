"""Strict M6 full conversion verification. Evidence and output paths must be new.

This runs the converter, measures the entire process, and verifies its exact published output.
Independent review and user-operated Outlook acceptance remain separate. No missing tool can pass.
Research probes are explicit arguments so their source/binary identity can be retained with evidence.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import sys
import time
import zlib


class GateFailure(RuntimeError):
    pass


def require(condition, detail):
    if not condition:
        raise GateFailure(detail)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1048576), b''):
            digest.update(part)
    return digest.hexdigest()


def validate_fixed_maps(path):
    """Check every reserved map in a Unicode 512 PST, independently of the writer.

    MS-PST 1.3.2.7/8, 2.2.2.7.1/2/3/5/6, 2.6.1.1.2: preserve all map pages.
    Placement after AMap/PMap is inferred from one sample, not in MS-PST or libpff
    notes; SCANPST requires FMap 0x1F04800+n*125960192 and FPMap 0x7C004800.
    M6 research/outlook-root-open-failure.md retains the diagnostic evidence.
    """
    counts = dict(AMap=0, PMap=0, FMap=0, FPMap=0)
    size = Path(path).stat().st_size
    require(size >= 0x4400 + 253952 and (size - 0x4400) % 253952 == 0,
            'fixed maps: physical EOF does not back whole AMap regions')
    with Path(path).open('rb') as file:
        header = file.read(512)
        require(len(header) == 512 and header[:4] == b'!BDN' and header[8:10] == b'SM' and
                struct.unpack_from('<H', header, 10)[0] == 23,
                'fixed maps: expected Unicode 512 PST output, never apply this layout to 4K OST')
        require(struct.unpack_from('<Q', header, 0xB8)[0] == size,
                'fixed maps: header EOF differs from physical EOF')
        regions = (size - 0x4400) // 253952
        for region in range(regions):
            base = 0x4400 + region * 253952
            pages = [('AMap', 0x84, base)]
            next_page = base + 512
            if region % 8 == 0:
                pages.append(('PMap', 0x83, next_page))
                next_page += 512
            if region >= 128 and (region - 128) % 496 == 0:
                pages.append(('FMap', 0x82, next_page))
                next_page += 512
            if region >= 8192 and (region - 8192) % 31744 == 0:
                pages.append(('FPMap', 0x85, next_page))
            amap = None
            for name, ptype, at in pages:
                file.seek(at)
                page = file.read(512)
                require(len(page) == 512, f'{name} page truncated at {at:#x}')
                actual_type, repeated, signature, crc, back = struct.unpack_from('<BBHIQ', page, 496)
                require((actual_type, repeated, signature, back) == (ptype, ptype, 0, at),
                        f'{name} trailer missing or invalid at {at:#x}')
                require(crc == (zlib.crc32(page[:496], 0xFFFFFFFF) ^ 0xFFFFFFFF),
                        f'{name} CRC mismatch at {at:#x}')
                if name == 'AMap':
                    amap = page[:496]
                first_bit = (at - base) // 64
                require(all(amap[bit // 8] & (0x80 >> (bit % 8))
                            for bit in range(first_bit, first_bit + 8)),
                        f'{name} page is unallocated in AMap at {at:#x}')
                counts[name] += 1
    return dict(result='PASS', pages=counts)


def validate_report(report, records, source_hash, size):
    require(report.get('schema') == 1 and report.get('status') == 'complete' and
            report.get('exit_code') == 0 and report.get('internal_verification') == 'passed',
            'conversion did not report complete verified output')
    require(report.get('source_sha256') == source_hash and report.get('pst_bytes') == size,
            'report is not bound to these source/output bytes')
    for field in ('skipped_corrupt', 'skipped_unsupported', 'failed',
                  'unknown_source_populations', 'unknown_read_state'):
        require(report.get(field) == 0, f'incomplete or missing {field}')
    require(report.get('source') == report.get('committed') == report.get('output_verified') and
            isinstance(report.get('source'), dict), 'source/committed/verified populations differ')
    items = [r for r in records if r.get('kind') == 'item']
    require(len(items) == report.get('items') == report.get('terminal') and len(items) > 0,
            'missing terminal item records')
    require(len({r['source_nid'] for r in items}) == len(items) and
            len({r['output_nid'] for r in items}) == len(items), 'duplicate source/output item identity')
    require(all(r.get('schema') == 1 and r.get('status') == 'converted' and
                r.get('source_complete') is True and r.get('source') == r.get('committed')
                for r in items), 'item records contain unavailable or uncarried content')
    require(sum(r['associated'] is True for r in items) == report.get('converted_fai') and
            sum(r['associated'] is False for r in items) == report.get('converted_normal'),
            'normal/FAI denominators differ')
    population_fields = {'embedded', 'recipients', 'attachments', 'opaque_objects', 'attachment_bytes'}
    require(set(report['source']) == population_fields, 'population fields are incomplete')
    for field in population_fields:
        values = [r['source'].get(field) for r in items]
        require(all(type(value) is int and value >= 0 for value in values) and
                sum(values) == report['source'][field], f'item/global {field} populations differ')
    coverage = [r for r in records if r.get('kind') == 'coverage']
    observed = {}
    for record in coverage:
        observed[record['status']] = observed.get(record['status'], 0) + 1
    require(observed == report.get('coverage') and
            len({r['source_nid'] for r in coverage}) == len(coverage),
            'coverage ledger missing, duplicated or inconsistent')
    require(all(r.get('schema') == 1 and r.get('status') in
                ('content', 'regenerated', 'excluded-search', 'unknown') for r in coverage),
            'unknown coverage schema/status')
    folders = {r['source_nid']: r for r in coverage if r['source_nid'] & 31 == 2}
    require(len(folders) == report.get('folders') and all(
        r['status'] == 'content' and r.get('output_nid', 0) > 0 for r in folders.values()) and
        len({r['output_nid'] for r in folders.values()}) == len(folders),
        'actual-folder mapping is incomplete')
    mapped_items = {r['source_nid']: r for r in coverage if r['source_nid'] & 31 in (4, 8)}
    require(set(mapped_items) == {r['source_nid'] for r in items},
            'item ledger differs from source coverage')
    for item in items:
        mapping = mapped_items[item['source_nid']]
        parent = folders.get(item.get('source_parent'))
        require(mapping['status'] == 'content' and
                mapping.get('output_nid') == item['output_nid'] and
                mapping.get('source_parent') == item.get('source_parent') and parent is not None and
                parent['output_nid'] == item.get('output_parent') and
                item.get('associated') is (item['source_nid'] & 31 == 8),
                'item mapping/type/parent differs from coverage')
    return items


def validate_metrics(metrics):
    require(0 < metrics.get('wall_seconds', 0) < 900, 'full conversion exceeds 900 seconds')
    require(0 < metrics.get('peak_working_set', 0) < 1000000000,
            'full conversion exceeds 1 GB or has no measured peak')


def validate_independent(independent, report):
    require(independent.get('result') == 'PASS' and independent.get('items') == report['items'] and
            independent.get('fai_items') == report['converted_fai'] and
            independent.get('folder_tables') == 2 * report['folders'],
            'independent normal/FAI/empty-folder coverage is incomplete')


def run(command, log, cwd=None, measured=False):
    require(Path(command[0]).is_file(), f'NOT VERIFIED: missing tool {command[0]}')
    metrics = None
    with Path(log).open('xb') as output:
        if measured:
            require(sys.platform == 'win32', 'NOT VERIFIED: Windows process memory measurement unavailable')
            from ctypes import wintypes
            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in ('peak', 'working', 'peak_paged', 'paged',
                                                       'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile')]
            query = ctypes.WinDLL('psapi').GetProcessMemoryInfo
            query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            query.restype = wintypes.BOOL
            started = time.perf_counter()
            child = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
            peak = 0
            while True:
                memory = Counters()
                memory.cb = ctypes.sizeof(memory)
                if query(int(child._handle), ctypes.byref(memory), memory.cb):
                    peak = max(peak, memory.peak)
                if child.poll() is not None:
                    break
                time.sleep(.1)
            metrics = {'wall_seconds': time.perf_counter() - started, 'peak_working_set': peak}
            code = child.returncode
        else:
            code = subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT).returncode
    require(code == 0, f'FAIL: {command[0]} exited {code}; see {log}')
    return metrics


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'candidate', 'evidence', 'converter', 'ostinfo', 'libpff', 'pffinfo',
                 'pffexport', 'mapped_compare', 'refs', 'api_compare', 'export_compare',
                 'baseline_export', 'baseline_export_log'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    args = parser.parse_args()
    for name, value in vars(args).items():
        setattr(args, name, value.resolve())
    require(not any(Path(str(args.candidate) + suffix).exists()
                    for suffix in ('', '.work', '.report.json', '.items.jsonl')),
            'candidate/work path already exists; preserve it and choose a new path')
    args.evidence.mkdir(parents=True, exist_ok=False)
    index = {'schema': 1, 'result': 'FAIL', 'commands': [], 'source_sha256': sha256(args.source),
             'converter_sha256': sha256(args.converter)}
    def step(name, command, cwd=None, measured=False):
        log = args.evidence / (name + '.txt')
        index['commands'].append({'name': name, 'command': list(map(str, command)), 'log': str(log)})
        index['commands'][-1]['tool_sha256'] = sha256(command[0]) if Path(command[0]).is_file() else None
        return run(list(map(str, command)), log, cwd, measured)
    try:
        index['metrics'] = step('conversion', [args.converter, args.source, args.candidate], measured=True)
        (args.evidence / 'metrics.json').write_text(json.dumps(index['metrics'], indent=2), encoding='utf-8')
        validate_metrics(index['metrics'])
        report = json.loads(Path(str(args.candidate) + '.report.json').read_text(encoding='utf-8'))
        ledger = Path(str(args.candidate) + '.items.jsonl')
        records = [json.loads(line) for line in ledger.read_text(encoding='utf-8').splitlines()]
        items = validate_report(report, records, index['source_sha256'], args.candidate.stat().st_size)
        candidate_hash = sha256(args.candidate)
        index['candidate_sha256'] = candidate_hash
        index['candidate_bytes'] = args.candidate.stat().st_size
        index['fixed_maps'] = validate_fixed_maps(args.candidate)
        (args.evidence / 'fixed-maps.json').write_text(json.dumps(index['fixed_maps'], indent=2),
                                                     encoding='utf-8')
        index['verification_inputs'] = {name: {'path': str(getattr(args, name)),
                                               'sha256': sha256(getattr(args, name))}
                                        for name in ('libpff', 'api_compare', 'export_compare',
                                                     'baseline_export_log')}
        for mode in ('probe', 'ndb', 'ltp'):
            step(mode, [args.ostinfo, '--' + mode, args.candidate])
            require('RESULT: clean' in (args.evidence / (mode + '.txt')).read_text(encoding='utf-8'),
                    f'{mode} lacks a clean completion verdict')
        step('references', [args.refs, args.candidate])
        references = (args.evidence / 'references.txt').read_text(encoding='utf-8')
        require(re.search(r'^blocks=[1-9][0-9]* shared=[0-9]+ max_ref=[0-9]+ unreferenced=0 mismatches=0 read_failures=0$',
                          references.strip()), 'reference audit is incomplete or inconsistent')
        step('mapped-content', [args.mapped_compare, args.source, args.candidate, args.evidence])
        mapped = (args.evidence / 'mapped-content.txt').read_text(encoding='utf-8')
        require(re.search(rf'^COMPLETE folders={report["folders"]} items={len(items)} ', mapped, re.M),
                'mapped source/output comparison did not finish the complete manifest')
        step('pffinfo', [args.pffinfo, args.candidate])
        step('libpff-pc', [Path(sys.executable), args.api_compare, args.libpff, args.source,
                           args.candidate, ledger, '--all'])
        independent = json.loads((args.evidence / 'libpff-pc.txt').read_text(encoding='utf-8'))
        validate_independent(independent, report)
        step('pffexport', [args.pffexport, '-q', '-f', 'all', '-t', 'export', args.candidate], args.evidence)
        export = (args.evidence / 'pffexport.txt').read_text(encoding='utf-8')
        require('Export completed.' in export, 'independent exporter stopped early')
        diagnostics = lambda text: [line for line in text.splitlines() if 'unable to' in line or 'unsupported' in line]
        warnings = diagnostics(export)
        baseline_warnings = diagnostics(args.baseline_export_log.read_text(encoding='utf-8'))
        require(warnings == baseline_warnings, 'new or different libpff export diagnostic')
        # Raw normal/FAI PC comparison complements the exporter's semantic interpretation.
        # All independently exported body/attachment bytes must also match the recorded baseline.
        index['export_interpretation_diagnostics'] = warnings
        step('export-bytes', [Path(sys.executable), args.export_compare, args.baseline_export,
                              args.evidence / 'export.export', args.candidate])
        comparison = json.loads((args.evidence / 'export-bytes.txt').read_text(encoding='utf-8'))
        require(comparison.get('mismatches') == 0, 'independent exported content differs')
        require(sha256(args.source) == index['source_sha256'], 'source changed during independent checks')
        require(sha256(args.candidate) == candidate_hash, 'candidate changed during independent checks')
        index.update(result='PASS', candidate_sha256=candidate_hash,
                     candidate_bytes=args.candidate.stat().st_size, report=report,
                     independent_pc=independent, exported_content=comparison)
    except (GateFailure, OSError, ValueError, KeyError) as error:
        index['error'] = str(error)
        raise
    finally:
        (args.evidence / 'gate.json').write_text(json.dumps(index, indent=2), encoding='utf-8')
    print(json.dumps(index, indent=2))


if __name__ == '__main__':
    main()
