configure_file(
  input: '@0@.desktop.in'.format(service_name),
  output: '@BASENAME@',
  configuration: conf,
  install_dir: datadir / 'applications',
)

configure_file(
  input: '@0@.portal.in'.format(service_name),
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
  input: '@0@.service.in'.format(dbus_name),
  output: '@BASENAME@',
  configuration: conf,
  install_dir: dbus_service_dir,
)
