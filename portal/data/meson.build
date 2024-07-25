configure_file(
  input: 'oo7-portal.desktop.in',
  output: 'oo7-portal.desktop',
  configuration: libexecdir_conf,
  install_dir: datadir / 'applications',
)

install_data(
  'oo7-portal.portal',
  install_dir: portal_dir,
)

if systemduserunitdir != ''
  configure_file(
    input: 'oo7-portal.service.in',
    output: 'oo7-portal.service',
    configuration: libexecdir_conf,
    install_dir: systemduserunitdir,
  )
endif

configure_file(
  input: 'org.freedesktop.impl.portal.desktop.oo7.service.in',
  output: 'org.freedesktop.impl.portal.desktop.oo7.service',
  configuration: libexecdir_conf,
  install_dir: dbus_service_dir,
)
