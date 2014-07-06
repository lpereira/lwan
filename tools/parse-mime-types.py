#!/usr/bin/python

import sys
import struct
try:
  import zopfli as zlib
except:
  import zlib
from operator import itemgetter

def to_bytes(s):
  try:
    return bytes(s, 'ascii')
  except TypeError:
    return bytes(s)

def pack_string(s):
  return struct.pack('%dsb' % len(s), to_bytes(s), 0)

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
  out += pack_string(ext)
  out += pack_string(typ)

compressed_out = zlib.compress(out, 9)

print('#ifndef __MIME_TYPES_H__')
print('#define __MIME_TYPES_H__')
print('/* Auto generated from parse-mime-types.py, do not modify */')

print('#define MIME_UNCOMPRESSED_LEN %d' % len(out))
print('#define MIME_COMPRESSED_LEN %d' % len(compressed_out))
print('#define MIME_ENTRIES %d' % entries)

print('struct mime_entry {')
print('  const char *extension;')
print('  const char *type;')
print('};')

print('static const unsigned char mime_entries_compressed[] = {')
line = []
for index, b in enumerate(compressed_out):
  if index > 0 and index % 13 == 0:
    print(' '.join(line))
    line = []

  if isinstance(b, str):
    b = ord(b)
  if b < 0x10:
    line.append('0x0%x,' % b)
  else:
    line.append('0x%x,' % b)

if line:
  print(' '.join(line))

print('};')

print('#endif  /* __MIME_TYPES_H__ */')
