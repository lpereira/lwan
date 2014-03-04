#!/usr/bin/python

import struct
import zlib

known_exts = set()
types = []
for l in file('/etc/mime.types'):
  l = l.strip()
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

types.sort(lambda a, b: cmp(a[1], b[1]))

max_ext_len = max(len(ext) for typ, ext in types)
max_typ_len = max(len(typ) for typ, ext in types)
total_len = len(types) * (max_ext_len + 1 + max_typ_len + 1)

out = ''
entries = 0
for typ, ext in types:
  entries += 1
  out += struct.pack('%ds' % len(ext), ext)
  out += struct.pack('b', 0)
  out += struct.pack('%ds' % len(typ), typ)
  out += struct.pack('b', 0)

compressed_out = zlib.compress(out, 9)

print '#ifndef __MIME_TYPES_H__'
print '#define __MIME_TYPES_H__'
print '/* Auto generated from parse-mime-types.py, do not modify */'

print '#define MIME_UNCOMPRESSED_LEN %d' % len(out)
print '#define MIME_COMPRESSED_LEN %d' % len(compressed_out)
print '#define MIME_ENTRIES %d' % entries

print 'struct mime_entry {'
print '  const char *extension;'
print '  const char *type;'
print '};'

print 'static const unsigned char mime_entries_compressed[] = {'
for index, b in enumerate(compressed_out):
  if index > 0 and index % 13 == 0:
    print ''

  b = ord(b)
  if b < 0x10:
    print '0x0%x,' % b,
  else:
    print '0x%x,' % b,
print '};'

print '#endif  /* __MIME_TYPES_H__ */'
