libcurl = dependency('libcurl')

add_languages('cpp')

args_update = {
  'dependencies': contrib_mod_args.get('dependencies') + [libcurl],
  'cpp_args': contrib_mod_args.get('cpp_args') + ['-std=c++23'],
}

mod_args = contrib_mod_args + args_update

pg_oidc_validator_sources = files(
  'src/pg_oidc_validator.cpp',
  'src/http_client.cpp',
  'src/jwk.cpp',
  'src/provisioning.cpp',
)

pg_oidc_validator = shared_module('pg_oidc_validator',
  pg_oidc_validator_sources,
  kwargs: mod_args,
  include_directories: ['jwt-cpp/include/'],
)

contrib_targets += pg_oidc_validator

install_data('pg_oidc_identity.control', 'sql/pg_oidc_identity--1.0.sql',
  kwargs: contrib_data_args)
