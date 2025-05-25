project('et', 'c',
  version: '0.1.0',

  default_options : [
    'c_std=c11',          # keep the language level
  ]
)

cc = meson.get_compiler('c')

# ────────────────────────────────────────────
#  External dependencies
# ────────────────────────────────────────────
openssl_dep = dependency('openssl', version : '3.1.9', required : true)

# ────────────────────────────────────────────
#  Targets
# ────────────────────────────────────────────
server_exe = executable('et_server',
  'server.c',
  dependencies : [openssl_dep],
  install      : true
)

client_exe = executable('et_client',
  'client.c',
  dependencies : [openssl_dep],
  install      : true
)
