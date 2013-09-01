#!/usr/bin/python

types = []

for l in file('/etc/mime.types'):
  l = l.strip()
  try:
    last_tab = l.rindex('\t')
  except ValueError:
    continue
  mime_type = l[:last_tab].strip()
  extensions = l[last_tab:].split()

  types.append((mime_type, extensions))

print '#ifndef MIME_TYPES_H'
print '#define MIME_TYPES_H'
print '/* Auto generated from parse-mime-types.py */'
print ''
print 'struct lwan_mime_type_t {'
print '   const char *mime_type;'
print '   const char *extension;'
print '};'
print ''
print 'static const struct lwan_mime_type_t mime_type_array[] = {'

for t, exts in types:
  for e in exts:
    print '   { .mime_type = \"%s\", .extension = \"%s\" },' % (t, e)

print '};'
print '#endif /* MIME_TYPES_H */'
