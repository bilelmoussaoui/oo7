project('oo7-gobject', ['c', 'rust'],
  version: '0.6.0',
  license: 'MIT',
  meson_version: '>= 1.7',
)

prefix = get_option('prefix')
libdir = get_option('libdir')
includedir = get_option('includedir')

# Dependencies
glib_dep = dependency('glib-2.0', version: '>= 2.56')
gobject_dep = dependency('gobject-2.0', version: '>= 2.56')
gio_dep = dependency('gio-2.0', version: '>= 2.56')

# Cargo build
cargo = find_program('cargo')

cargo_options = ['--target-dir', meson.project_build_root()]

if get_option('buildtype') == 'release'
  cargo_options += ['--release']
  rust_target = 'release'
else
  rust_target = 'debug'
endif

# Build the Rust library
rust_lib = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: 'liboo7.so',
  console: true,
  install: true,
  install_dir: libdir,
  command: [
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', rust_target / 'liboo7.so', '@OUTPUT@',
  ]
)

# Headers
headers = [
  'src/oo7.h',
]

install_headers(headers, subdir: 'oo7-1.0')

# pkg-config
pkg = import('pkgconfig')
pkg.generate(
  name: 'oo7-1.0',
  description: 'GObject bindings for oo7 - Linux Secret Service API',
  version: meson.project_version(),
  libraries: ['-L${libdir}', '-loo7'],
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0'],
  subdirs: 'oo7-1.0',
)

# Tests
test_keyring = executable(
  'test-keyring',
  'tests/test_keyring.c',
  dependencies: [glib_dep, gobject_dep, gio_dep],
  link_with: rust_lib,
  include_directories: include_directories('src'),
)

test('keyring', test_keyring)

