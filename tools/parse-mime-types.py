#!/usr/bin/python

import sys
import struct
import zlib
from operator import itemgetter

known_exts = set()
types = []
for l in open(sys.argv[1]):
  l = l.strip()
  if l.startswith('#'):
    continue
  if '#' in l:
    l = l.split('#')[0].strip()
  try:
    last_tab = l.rindex('\t')
  except ValueError:
    continue
  mime_type = l[:last_tab].strip()
  for extension in l[last_tab:].split():
    if extension in known_exts:
      continue
    known_exts.add(extension)
    types.append((mime_type, extension))

types.sort(key = itemgetter(1))

max_ext_len = max(len(ext) for typ, ext in types)
max_typ_len = max(len(typ) for typ, ext in types)
total_len = len(types) * (max_ext_len + 1 + max_typ_len + 1)

out = b''
entries = 0
for typ, ext in types:
  entries += 1
  out += struct.pack(str(len(ext)) + 's', bytes(ext, 'ascii'))
  out += struct.pack('b', 0)
  out += struct.pack(str(len(typ)) + 's', bytes(typ, 'ascii'))
  out += struct.pack('b', 0)

compressed_out = zlib.compress(out, 9)

print('#ifndef __MIME_TYPES_H__')
print('#define __MIME_TYPES_H__')
print('/* Auto generated from parse-mime-types.py, do not modify */')

print('#define MIME_UNCOMPRESSED_LEN', len(out))
print('#define MIME_COMPRESSED_LEN', len(compressed_out))
print('#define MIME_ENTRIES', entries)

print('struct mime_entry {')
print('  const char *extension;')
print('  const char *type;')
print('};')

print('static const unsigned char mime_entries_compressed[] = {')
for index, b in enumerate(compressed_out):
  if index > 0 and index % 13 == 0:
    print()

  if b < 0x10:
    print('0x0%x,' % b, end=' ')
  else:
    print('0x%x,' % b, end=' ')
print('};')

print('#endif  /* __MIME_TYPES_H__ */')
