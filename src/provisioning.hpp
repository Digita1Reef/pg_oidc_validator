#pragma once

#include <string>

namespace oidc {

// Called by the module's _PG_init(). An empty management_database disables JIT.
void register_provisioning_settings();
bool provisioning_enabled();

// Called only after token/identity/claim validation, during authentication.
// request_json contains validated claims, never the bearer token. The helper
// returns true only after the worker has committed a successful reconciliation.
bool provision_identity(const std::string& request_json);

}  // namespace oidc
