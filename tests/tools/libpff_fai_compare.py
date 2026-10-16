"""Read-only independent FAI PC/ownership comparison through the installed libpff DLL.

No mailbox payload is logged. The item ledger supplies the declared mapping, never decoded values.
libpff.h.in declares the APIs used here. This complements, rather than replaces, recursive mapped
content comparison and pffexport. API errors are failures, not unavailable values.
"""
import ctypes as C
import hashlib
import json
from collections import defaultdict
from pathlib import Path
import sys


class Pff:
    def __init__(self, dll):
        self.lib = C.CDLL(str(Path(dll).resolve()))
        self.err = C.c_void_p()
        self.p = C.c_void_p
        self.pp = C.POINTER(self.p)
        p, pp = self.p, self.pp
        signatures = {
            'file_initialize': [pp, pp], 'file_open': [p, C.c_char_p, C.c_int, pp],
            'file_close': [p, pp], 'file_free': [pp, pp],
            'file_get_item_by_identifier': [p, C.c_uint32, pp, pp],
            'item_free': [pp, pp], 'item_get_identifier': [p, C.POINTER(C.c_uint32), pp],
            'item_get_number_of_record_sets': [p, C.POINTER(C.c_int), pp],
            'item_get_record_set_by_index': [p, C.c_int, pp, pp],
            'record_set_free': [pp, pp],
            'record_set_get_number_of_entries': [p, C.POINTER(C.c_int), pp],
            'record_set_get_entry_by_index': [p, C.c_int, pp, pp],
            'record_entry_free': [pp, pp],
            'record_entry_get_entry_type': [p, C.POINTER(C.c_uint32), pp],
            'record_entry_get_value_type': [p, C.POINTER(C.c_uint32), pp],
            'record_entry_get_name_to_id_map_entry': [p, pp, pp],
            'record_entry_get_data_size': [p, C.POINTER(C.c_size_t), pp],
            'record_entry_get_data': [p, p, C.c_size_t, pp],
            'name_to_id_map_entry_get_type': [p, C.POINTER(C.c_uint8), pp],
            'name_to_id_map_entry_get_number': [p, C.POINTER(C.c_uint32), pp],
            'name_to_id_map_entry_get_utf8_string_size': [p, C.POINTER(C.c_size_t), pp],
            'name_to_id_map_entry_get_utf8_string': [p, p, C.c_size_t, pp],
            'name_to_id_map_entry_get_guid': [p, p, C.c_size_t, pp],
            'folder_get_number_of_sub_associated_contents': [p, C.POINTER(C.c_int), pp],
            'folder_get_sub_associated_content': [p, C.c_int, pp, pp],
            'folder_get_number_of_sub_messages': [p, C.POINTER(C.c_int), pp],
            'folder_get_sub_message': [p, C.c_int, pp, pp],
        }
        for name, args in signatures.items():
            fn = getattr(self.lib, 'libpff_' + name)
            fn.argtypes, fn.restype = args, C.c_int

    def call(self, name, *args, expected=1):
        code = getattr(self.lib, 'libpff_' + name)(*args, C.byref(self.err))
        if code != expected:
            detail = C.create_string_buffer(8192)
            self.lib.libpff_error_backtrace_sprint(self.err, detail, len(detail))
            raise RuntimeError(f'{name}: {code}: {detail.value.decode("utf-8", "replace")}')
        return code

    def scalar(self, name, obj, kind=C.c_uint32):
        value = kind()
        self.call(name, obj, C.byref(value))
        return value.value

    def open(self, path):
        obj = self.p()
        self.call('file_initialize', C.byref(obj))
        self.call('file_open', obj, str(Path(path).resolve()).encode('utf-8'), 1)
        return obj

    def item(self, file, nid):
        obj = self.p()
        self.call('file_get_item_by_identifier', file, nid, C.byref(obj))
        return obj

    def free(self, name, obj):
        self.call(name + '_free', C.byref(obj))

    def identity(self, entry, tag, value_type):
        if tag < 0x8000:
            return f'{tag:04x}:{value_type:04x}'
        named = self.p()
        self.call('record_entry_get_name_to_id_map_entry', entry, C.byref(named))
        guid = C.create_string_buffer(16)
        self.call('name_to_id_map_entry_get_guid', named, guid, 16)
        kind = self.scalar('name_to_id_map_entry_get_type', named, C.c_uint8)
        # libpff/definitions.h.in: public API types are ASCII 'n'/'s', not the wire N bit.
        if kind == ord('n'):
            name = str(self.scalar('name_to_id_map_entry_get_number', named))
        elif kind == ord('s'):
            size = self.scalar('name_to_id_map_entry_get_utf8_string_size', named, C.c_size_t)
            buf = C.create_string_buffer(size)
            self.call('name_to_id_map_entry_get_utf8_string', named, buf, size)
            # Compare the complete API string buffer, including its single terminator. Removing all
            # trailing zero bytes could conflate distinct counted names ending in U+0000.
            name = hashlib.sha256(buf.raw).hexdigest()
        else:
            raise RuntimeError(f'unsupported libpff NameID kind {kind}')
        return f'named:{guid.raw.hex()}:{kind}:{name}:{value_type:04x}'

    def properties(self, file, nid):
        item = self.item(file, nid)
        sets = self.scalar('item_get_number_of_record_sets', item, C.c_int)
        if sets != 1:
            raise RuntimeError(f'FAI {nid:x} has {sets} PC record sets')
        record_set = self.p()
        self.call('item_get_record_set_by_index', item, 0, C.byref(record_set))
        count = self.scalar('record_set_get_number_of_entries', record_set, C.c_int)
        result = {}
        for index in range(count):
            entry = self.p()
            self.call('record_set_get_entry_by_index', record_set, index, C.byref(entry))
            tag = self.scalar('record_entry_get_entry_type', entry)
            value_type = self.scalar('record_entry_get_value_type', entry)
            identity = self.identity(entry, tag, value_type)
            size = self.scalar('record_entry_get_data_size', entry, C.c_size_t)
            if size > 64 * 1024 * 1024:
                raise RuntimeError('independent probe value exceeds its 64 MiB workspace')
            buf = C.create_string_buffer(size)
            # get_data_size successfully reports zero for a present empty value. There are no
            # bytes to fetch; get_data rejects the missing backing pointer in this case.
            if size:
                self.call('record_entry_get_data', entry, buf, size)
            if identity in result:
                raise RuntimeError(f'duplicate PC identity {nid:x}/{identity}')
            result[identity] = (size, hashlib.sha256(buf.raw).hexdigest())
            self.free('record_entry', entry)
        self.free('record_set', record_set)
        self.free('item', item)
        return result


def main():
    dll, source_path, candidate_path, ledger_path = sys.argv[1:5]
    all_items = sys.argv[5:] == ['--all']
    records = [json.loads(line) for line in Path(ledger_path).read_text(encoding='utf-8').splitlines()]
    items = [r for r in records if r.get('kind') == 'item' and (all_items or r['associated'])]
    if not items or any(r['status'] != 'converted' for r in items):
        raise RuntimeError('FAI ledger absent or incomplete')
    api = Pff(dll)
    source, candidate = api.open(source_path), api.open(candidate_path)
    owners = defaultdict(set)
    compared = total_bytes = 0
    extras = defaultdict(int)
    for record in items:
        owners[(record['output_parent'], record['associated'])].add(record['output_nid'])
        left = api.properties(source, record['source_nid'])
        right = api.properties(candidate, record['output_nid'])
        for identity, data in left.items():
            if identity.startswith('0fff:'):  # Writer regenerates PST EntryIDs: MS-PST 2.4.3.2.
                continue
            if right.get(identity) != data:
                raise RuntimeError(f'PC mismatch {record["source_nid"]:x}/{identity}')
            compared += 1
            total_bytes += data[0]
        for identity in right.keys() - left.keys():
            extras[identity] += 1
    if all_items:
        for record in records:
            if record.get('kind') == 'coverage' and record['source_nid'] & 31 == 2:
                if record['status'] != 'content' or not record['output_nid']:
                    raise RuntimeError('actual folder has no preserved mapping')
                owners[(record['output_nid'], False)]
                owners[(record['output_nid'], True)]
    for (nid, associated), expected in owners.items():
        folder = api.item(candidate, nid)
        count_fn = 'folder_get_number_of_sub_associated_contents' if associated else 'folder_get_number_of_sub_messages'
        get_fn = 'folder_get_sub_associated_content' if associated else 'folder_get_sub_message'
        count = api.scalar(count_fn, folder, C.c_int)
        observed = set()
        for index in range(count):
            item = api.p()
            api.call(get_fn, folder, index, C.byref(item))
            identity = api.scalar('item_get_identifier', item)
            if identity in observed:
                raise RuntimeError('duplicate FAI table membership')
            observed.add(identity)
            api.free('item', item)
        if observed != expected:
            raise RuntimeError(f'FAI ownership mismatch {nid:x}: {len(observed)} vs {len(expected)}')
        api.free('item', folder)
    for file in (source, candidate):
        api.call('file_close', file, expected=0)
        api.free('file', file)
    print(json.dumps({'result': 'PASS', 'items': len(items),
                      'fai_items': sum(r['associated'] for r in items), 'folder_tables': len(owners),
                      'properties': compared, 'value_bytes': total_bytes,
                      'output_only_properties': dict(extras)}, indent=2))


if __name__ == '__main__':
    main()
