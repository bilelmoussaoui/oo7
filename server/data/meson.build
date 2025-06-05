if systemduserunitdir != ''
  configure_file(
    input: '@0@.service.in'.format(service_name),
    output: '@BASENAME@',
    configuration: libexecdir_conf,
    install_dir: systemduserunitdir,
  )
endif

configure_file(
  input: '@0@.service.in'.format(dbus_known_name),
  output: '@BASENAME@',
  configuration: libexecdir_conf,
  install_dir: dbus_service_dir,
)
