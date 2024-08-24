project(
  'oo7-portal',
  'rust',
  version: '0.1.0',
  meson_version: '>= 0.59.0',
)

dbus_name = 'org.freedesktop.impl.portal.desktop.oo7'
service_name = meson.project_name()
is_devel = get_option('profile') == 'development'

prefix = get_option('prefix')
datadir = get_option('datadir')
dbus_service_dir = get_option('dbus_service_dir')
if dbus_service_dir == ''
  dbus_service_dir = datadir / 'dbus-1' / 'services'
endif
libexecdir = get_option('libexecdir')

build_systemd_service = get_option('systemd')
systemduserunitdir = get_option('systemduserunitdir')
if systemduserunitdir == ''
  systemd = dependency('systemd', version: '>= 242', required: build_systemd_service)
  if build_systemd_service.allowed() and systemd.found()
    systemduserunitdir = systemd.get_variable(
      pkgconfig: 'systemduserunitdir',
      pkgconfig_define: ['prefix', prefix]
    )
  endif
endif

portal_dir = datadir / 'xdg-desktop-portal' / 'portals'

conf = configuration_data()
conf.set('libexecdir', prefix / libexecdir)
conf.set('dbus_name', dbus_name)
conf.set('service_name', service_name)
conf.set('bin_name', meson.project_name())

summary({
  'prefix': prefix,
  'datadir': datadir,
  'libexecdir': libexecdir,
  'dbus_service_dir': dbus_service_dir,
})

subdir('data')
subdir('src')
