project(
  'libucontext',
  'c',
  meson_version : '>=0.59.0',
  default_options: ['c_std=gnu11', 'default_library=both'],
  version : run_command('head', files('VERSION')).stdout()
)

cpu = get_option('cpu')
if cpu == ''
  cpu = host_machine.cpu_family()
endif

if cpu == 'sh4'
  cpu = 'sh'
endif

project_description = 'Portable implementation of ucontext'

project_headers = [
  'include/libucontext/libucontext.h'
]

project_source_files = [
  'arch' / cpu / 'getcontext.S',
  'arch' / cpu / 'setcontext.S',
  'arch' / cpu / 'swapcontext.S',
]
if cpu in ['mips', 'mips64']
  project_source_files += [
    'arch' / cpu / 'makecontext.S'
  ]
else
  project_source_files += [
    'arch' / cpu / 'makecontext.c'
  ]
endif
if cpu in ['ppc', 'ppc64']
  project_source_files += [
    'arch' / cpu / 'retfromsyscall.c'
  ]
endif
if cpu not in ['mips', 'mips64', 'ppc', 'ppc64', 's390x']
  project_source_files += [
    'arch' / cpu / 'trampoline.c'
  ]
else
  project_source_files += [
    'arch' / cpu / 'startcontext.S'
  ]
endif

project_includes = [
  'include',
  'arch/common'
]

build_args = [
  '-D_BSD_SOURCE'
]


# ===================================================================

# ======
# Options
# ======

freestanding = get_option('freestanding')
export_unprefixed = get_option('export_unprefixed')
build_posix = true

if freestanding
  build_args += '-DFREESTANDING'
  build_posix = false
  export_unprefixed = false
  project_headers += ['arch' / cpu / 'include/libucontext/bits.h']
  project_includes += ['arch' / cpu / 'include']
else
  project_headers += ['arch/common/include/libucontext/bits.h']
  project_includes += ['arch/common/include']
endif

if export_unprefixed
  build_args += '-DEXPORT_UNPREFIXED'
endif

# ======
# Target
# ======

headers = include_directories(project_includes)

libucontext_target = library(
  'ucontext',
  project_source_files,
  version: '1',
  install : not meson.is_subproject(),
  c_args : build_args,
  pic: true,
  include_directories : headers,
)
libucontext_dep = declare_dependency(
  include_directories: headers,
  link_with : libucontext_target
)

if build_posix
  libucontext_posix_target = library(
    'ucontext_posix',
    project_source_files + ['libucontext_posix.c'],
    version: '1',
    install : not meson.is_subproject(),
    c_args : build_args,
    pic: true,
    include_directories : headers,
  )
  libucontext_posix_dep = declare_dependency(
    include_directories: headers,
    link_with : libucontext_posix_target
  )
endif

# =======
# Project
# =======

if not meson.is_subproject()
  # Make this library usable from the system's
  # package manager.
  install_headers(project_headers, subdir : meson.project_name())

  pkg_mod = import('pkgconfig')
  pkg_mod.generate(
    name : meson.project_name(),
    filebase : meson.project_name(),
    description : project_description,
    subdirs : meson.project_name(),
    libraries : libucontext_target,
  )
endif

# ====
# Docs
# ====

if not meson.is_subproject() and get_option('docs')
  subdir('doc')
endif

# ==========
# Unit Tests
# ==========

test('test_libucontext',
  executable(
    'test_libucontext',
    files('test_libucontext.c'),
    dependencies : libucontext_dep,
    install : false
  )
)
if build_posix
  test('test_libucontext_posix',
    executable(
      'test_libucontext_posix',
      files('test_libucontext_posix.c'),
      dependencies : [libucontext_dep, libucontext_posix_dep],
      install : false
    )
  )
endif
