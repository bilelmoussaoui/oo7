if systemduserunitdir != ''
  configure_file(
    input: 'oo7-daemon.service.in',
    output: 'oo7-daemon.service',
    configuration: libexecdir_conf,
    install_dir: systemduserunitdir,
  )
endif

configure_file(
  input: 'org.freedesktop.secrets.service.in',
  output: 'org.freedesktop.secrets.service',
  configuration: libexecdir_conf,
  install_dir: dbus_service_dir,
)
