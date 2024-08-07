scdoc = find_program('scdoc', required: true)

custom_target(
  'libucontext.3',
  output: 'libucontext.3',
  input: 'libucontext.scd',
  command: [ scdoc ],
  feed: true,
  capture: true,
  install: true,
  install_dir: get_option('mandir') / 'man3'
)

if meson.version().version_compare('>=0.61.0')
  foreach link : [ 'get', 'make', 'set', 'swap' ]
    install_symlink('libucontext_' + link + 'context.3',
      pointing_to: 'libucontext.3',
      install_dir: get_option('mandir') / 'man3'
    )
  endforeach
endif
