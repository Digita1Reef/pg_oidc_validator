# pg_oidc_validator

OAuth validator library for PostgreSQL 18 and 19

This library should support most providers that implement OIDC and provide a valid JWT as an access token.

## Getting started

### Nightly builds

Experimental packages are available on github:

**Debian/Ubuntu:**
- Binaries for Ubuntu 24.04 are available [here](https://github.com/Percona-Lab/pg_oidc_validator/releases/tag/latest).

**RHEL/Oracle Linux/Rocky Linux:**
- RPM packages for OL8 and OL9 are available [here](https://github.com/Percona-Lab/pg_oidc_validator/releases/tag/latest).

### Building from Source

To build and install from sources, use `make USE_PGXS=1 install -j`.

  > **__NOTE__:** A a C++23 compiler and standard library is required to build pg_oidc_validator.

## Configuration

Enable the validator in `postgresql.conf`:

```conf
oauth_validator_libraries = 'pg_oidc_validator'
```

Configure the expected resource audience for your PostgreSQL version before enabling OAuth logins. The module compares this value with the signed access token's `aud` claim, which may be a string or an array containing that value. The token must also have a valid expiration time.

**PostgreSQL 19 and later** — Set `validator.audience` on each OAuth rule in `pg_hba.conf`. For example, these databases accept different resource audiences from the same issuer:

```conf
hostssl reports  analyst  192.0.2.0/24  oauth issuer="https://issuer.example" scope="connect" validator.audience="reports-api"
hostssl billing  analyst  192.0.2.0/24  oauth issuer="https://issuer.example" scope="connect" validator.audience="billing-api"
```

Before upgrading from PostgreSQL 18, prepare an audience for every OAuth HBA rule in the PostgreSQL 19 configuration. A missing or invalid per-rule audience denies login. The PostgreSQL 18 server-wide setting does not provide a fallback.

**PostgreSQL 18** — Set one `pg_oidc_validator.audience` in `postgresql.conf`. It applies to every OAuth rule on the server. For example:

```conf
pg_oidc_validator.audience = 'reports-api'
```

Use the corresponding HBA rule without the PostgreSQL 19 option:

```conf
hostssl reports  analyst  192.0.2.0/24  oauth issuer="https://issuer.example" scope="connect"
```

## Configuration variables

### pg_oidc_validator.authn_field

This variable controls which field of the provided JWT token is used for identity mapping.
By default this is the `sub` claim, as most providers allow the configuration of this claim to provide different user fields.

In some cases however the `sub` claim is fixed to a randomly generated, application specific identifier which is non known before a user first connects to the application.
This is not practical for mapping provider users to PostgreSQL users in a map file.
Selecting a different `authn_field`, such as `email` allows an easy to use persistent mapping in this case.

### pg_oidc_validator.discovery_url_override

This variable overrides the URL the validator uses for communication with the OIDC provider.
It is mainly intended for testing, but can be also used in environment where the provider has a different external/internal URL.

Setting this variable doesn't change the issuer used during JWT validation.

## Usage

Use a TLS connection to the server with its certificate authority trusted by the client.

Example with `psql`:

```
psql 'host=db.example.com sslmode=verify-full dbname=name oauth_issuer=https://url.to.the.oidc.issuer oauth_client_id=client-id-registered-in-provider oauth_client_secret=optional-client-secret'
```

  > **__NOTE__:** `oauth_client_secret` is only necessary if the provider is configured to require one.

## OIDC provider specific instructions

### Keycloak
Keycloak is easy to run locally using podman or docker for trying things out.

Remember to enable the OAuth 2 device flow for the client configured in Keycloak, since that's the only OAuth flow the command line tools support.

The below example is for a client with id "postgres" and an included scope called "database" being allowed to login with the PostgreSQL access role `rolename`.

Example PostgreSQL 19 HBA entry:
```
host	all	rolename	127.0.0.1/32	oauth	scope="database" issuer=https://127.0.0.1:8080/realms/master validator.audience=postgresql-resource
```

Connection example:
```
psql 'host=127.0.0.1 dbname=name user=rolename oauth_issuer=https://127.0.0.1:8080/realms/master oauth_client_id=postgres'
```

### Microsoft / Entra ID
* `oauth_issuer` for postgres should be `https://login.microsoftonline.com/<tenant_id>/v2.0`
* For v2 access tokens, use the PostgreSQL resource application's client ID (GUID) as the audience for your PostgreSQL version. Expose a delegated permission on that application, and request its full name, such as `api://<resource-app-id>/connect`, in the OAuth HBA rule. The token must include the corresponding permission in `scp`.
* For existing database roles, use `pg_oidc_validator.authn_field = 'oid'` and map the user's object ID from the configured tenant to a database role in `pg_ident.conf`. Use a `hostssl` rule for those roles and retain the existing HBA rules for service accounts. Leave `delegate_ident_mapping` disabled so PostgreSQL verifies the requested role. The optional provisioning mode below creates individual roles automatically instead.

### Individual Entra identities and permission profiles

This fork includes an opt-in provisioning extension for a writable PostgreSQL
primary. It is disabled by default. It does not change SCRAM service accounts or
OAuth rules that use PostgreSQL identity mapping. Deploy it only after reviewing
the permission map and testing it on a disposable cluster.
Build this branch to use the feature; upstream nightly packages do not include it.

For a delegated login, the validator verifies signature, exact issuer, audience,
expiry and delegated scope before accepting Entra's `roles` claim. It binds the
identity to the tenant's immutable `tid` and `oid`. The requested PostgreSQL
username must exactly match `preferred_username` (at most 63 UTF-8 bytes).
Permissions come from an administrator-maintained map, never from SQL inferred
from a claim's name. ID tokens and application-only tokens are not accepted.

A native PostgreSQL background worker connects to one management database and
reconciles the individual login role in a transaction before authentication
continues. This is necessary because the authenticating backend has not yet
initialized its database session. No external synchronizer, Graph credential,
shared human login or client-supplied SQL is used. At login, `current_user`, `session_user`
and `pg_stat_activity.usename` identify the individual SQL role; `system_user`
records `oauth:<tenant UUID>:<object UUID>` independently of a username change.
An authorized `SET ROLE` changes `current_user` to the technical role;
`session_user` and `system_user` retain the individual's identity.
The implementation uses PostgreSQL's [delegated OAuth callback contract](https://www.postgresql.org/docs/18/oauth-validator-callbacks.html)
and [native background-worker API](https://www.postgresql.org/docs/18/bgworker.html).

Suggested app-role catalogue:

| Entra app role | PostgreSQL grant | Scope |
| --- | --- | --- |
| `CLUSTER.MONITOR` | `pg_monitor` | Cluster monitoring |
| `CLUSTER.SESSION_OPERATOR` | `pg_signal_backend` | Cancel/terminate non-superuser sessions across the cluster |
| `CLUSTER.SUPERUSER` | Individual `SUPERUSER` attribute | Entire cluster; bypasses all ordinary controls |
| `<database>.READ_ONLY` | `CONNECT`, schema `USAGE`, table/view and sequence `SELECT` | Explicit application schemas |
| `<database>.READ_WRITE` | Read plus table `INSERT`, `UPDATE`, `DELETE`, sequence `USAGE` | No DDL, `TRUNCATE` or sequence `setval` |
| `<database>.EXECUTE` | `EXECUTE` on named functions/procedures | Explicit routines only |
| `<database>.MAINTAIN` | Table `MAINTAIN` | Explicit schemas, without cluster-wide `pg_maintain` |
| `<database>.OWNER` | Technical `NOLOGIN` role owns selected resources | Can change grants and drop owned resources; opt-in `SET ROLE` |

These labels are examples: configure the exact Entra app-role values in the map.
`SUPERUSER` is an explicit attribute, not an inherited group privilege. Ordinary
profiles grant neither ownership nor `BYPASSRLS`; existing view and
`SECURITY DEFINER` routine security semantics still apply. Owners can change
RLS and normally bypass it on owned tables.
SQL grants are additive: inspect existing `PUBLIC`, direct and transitive grants,
including database `CONNECT`/`TEMP` and routine `EXECUTE`. This extension does not
revoke unrelated grants. The profile helper adds grants and does not remove
previous grants when its resource list shrinks. Review those changes explicitly.

#### Configure permission groups and the management database

As an administrator, install the extension in each target database where the
profile helper is used. Configure explicit schemas and every role that creates
future objects; default privileges belong to each creator, not to a database.
The helper creates technical `NOLOGIN` roles. READ_ONLY, READ_WRITE and MAINTAIN
apply grants to existing objects plus the specified creators' future objects;
EXECUTE names individual routines and OWNER uses explicit technical ownership.
For example, while connected to `reports`:

```sql
CREATE EXTENSION pg_oidc_identity;
SELECT oidc_identity.configure_profile(
  'reports_reader', 'READ_ONLY', ARRAY['app']::name[], ARRAY['app_owner']::name[]);
SELECT oidc_identity.configure_profile(
  'reports_writer', 'READ_WRITE', ARRAY['app']::name[], ARRAY['app_owner']::name[]);
```

Then, in the single management database (here `postgres`):

```sql
CREATE EXTENSION pg_oidc_identity;
INSERT INTO oidc_identity.configuration (singleton, tenant_id)
VALUES (true, '11111111-1111-4111-8111-111111111111');

INSERT INTO oidc_identity.entitlements (claim, sql_roles) VALUES
  ('reports.READ_ONLY', ARRAY['reports_reader']::name[]),
  ('reports.READ_WRITE', ARRAY['reports_writer']::name[]);
-- Only if full cluster administration is intended:
INSERT INTO oidc_identity.entitlements (claim, superuser)
VALUES ('CLUSTER.SUPERUSER', true);
```

For `EXECUTE`, provide `routines => ARRAY['app.report(integer)'::regprocedure]`.
For `OWNER`, list the schemas, `owned_relations` and `routines` to transfer;
`own_database => true` also transfers the current database. Existing objects are
not transferred merely because their schema changes owner. Include the technical
owner in both `sql_roles` and `owner_roles` in the central entitlement to allow
`SET ROLE` for future object creation under that owner. Other memberships use
`SET FALSE` and all managed memberships use `ADMIN FALSE`.

Use a trusted, administrator-owned management database. The management
tables/functions are private to superuser administrators. Do not
grant application users write access or expose the reconciliation function as a
`SECURITY DEFINER` wrapper. Keep the registry in only one management database;
its identity records and historical username reservations must be backed up
with the cluster. Pre-existing SQL roles are never silently adopted.

#### Enable delegated login

Configure the primary and reload its configuration:

```conf
oauth_validator_libraries = 'pg_oidc_validator'
pg_oidc_validator.management_database = 'postgres'
pg_oidc_validator.identity_tenant = '11111111-1111-4111-8111-111111111111'
```

Add a `hostssl` OAuth HBA rule with `delegate_ident_mapping=1`, the exact
tenant-specific Entra issuer and resource scope. Set the audience using the
PostgreSQL-version-specific setting above. Place existing service-account rules
first. Scope the rule's databases and client addresses to the intended access;
do not use `+group` to match a user's first login before their role exists.
The provisioning mode accepts tenant-specific public-cloud Entra v2 and v1
issuers only. The tenant pin must match the management database configuration.

Connections to standbys fail closed in this mode: reconciliation writes require
the primary. Worker-slot or shared-memory exhaustion also denies authentication.
Budget `max_worker_processes` for expected login concurrency alongside other
workers. Each reconciliation is bounded by the connection's existing
`authentication_timeout`; a failed or cancelled login never reports success.
A transaction already committed immediately before a client disconnect remains
committed and is safe to reconcile again.

#### Role changes, revocation and session settings

Each new connection reconciles the current signed app-role assignments. Missing
or empty `roles` removes managed grants and `SUPERUSER`, then denies login.
Unknown roles, ambiguous timestamps or an older token attempting to restore
changed privileges deny login. Concurrent first logins are serialized. Username
changes preserve the same SQL role OID, and historical names cannot be reused by
another immutable identity.

Removing an Entra assignment stops issuance of new authorized tokens; already
issued tokens may remain usable until expiry unless superseded by a newer
incompatible claim snapshot or otherwise rejected. Existing SQL sessions are not
terminated or reauthenticated by this extension. In particular, a session that
already initialized with `SUPERUSER` may retain it until disconnected. Immediate
incident response still requires terminating the affected sessions. Token
renewal belongs to the client, not the validator.
Ownership, direct grants and privileges delegated by an administrator are not
automatically swept when an assignment changes. A former owner or superuser
requires an explicit privilege audit; this integration cannot constrain a SQL
superuser's ability to persist privileged changes.

Optional `settings` on an entitlement configure only PostgreSQL's
`idle_session_timeout`, `idle_in_transaction_session_timeout`, `statement_timeout`,
`lock_timeout` and `transaction_timeout`. Use `"0"` or integer milliseconds such
as `{"idle_session_timeout":"600000ms"}`; no other settings are accepted.
Conflicting settings across assigned profiles deny login. An omitted setting
inherits effective PostgreSQL defaults. Removing a managed override resets it
to defaults or restores a pre-existing explicit role setting, preserving
unrelated settings. Role settings apply to new sessions, not existing ones.
These native user-settable defaults are not a non-bypassable session lifetime;
database-specific role settings and client/session overrides may take precedence.

## Google OIDC
Google has some quirks which are currently not supported by the libpq device code implementation.
It is only usable with custom clients that do not rely on the internal device flow.

## Dex
Dex doesn't support OAuth scopes, it doesn't include the parameter in the tokens.
While the use of scopes is strongly recommended for OAuth, and the parameter is required in pg_hba, it can be the empty string.
Specifying `scope=""` disables scope validation.

## Testing

The validator has a basic test suite, documented under [test/README.md](test/README.md).

## Examples

Examples can be found in the `examples` folder.
Currently there's only a single [Keycloak](examples/keycloak/README.md) example.
