configure_file(
  input: 'oo7-portal.desktop.in',
  output: '@BASENAME@',
  configuration: conf,
  install_dir: datadir / 'applications',
)

configure_file(
  input: 'oo7-portal.portal.in',
  output: '@BASENAME@',
  configuration: conf,
  install_dir: portal_dir,
)

if systemduserunitdir != ''
  configure_file(
    input: '@0@.service.in'.format(service_name),
    output: '@BASENAME@',
    configuration: conf,
    install_dir: systemduserunitdir,
  )
endif

configure_file(
  input: 'org.freedesktop.impl.portal.desktop.oo7.service.in',
  output: '@BASENAME@',
  configuration: conf,
  install_dir: dbus_service_dir,
)
