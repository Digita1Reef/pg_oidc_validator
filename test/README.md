# OAuth integration tests

## Per-database audience routing

Install the module into a PostgreSQL 18 or 19 test installation. Install Python 3
and its `cryptography` package, then run from the repository root as a non-root
user. Build the example libpq client against the same PostgreSQL installation.

```sh
make USE_PGXS=1 PG_CONFIG="$(command -v pg_config)" oauth_conn_test
PGBIN="$(pg_config --bindir)" python3 test/hba_audience.py
```

This test creates a disposable PostgreSQL server accessible only through a private
Unix socket. A loopback fixture serves temporary discovery data and a public key.
On PostgreSQL 19, two databases accept only the access token for their configured
audience. A rule without an audience rejects the connection even when the server
setting matches. On 18, both databases use the server setting.

## Individual identity provisioning

After installing the module and `pg_oidc_identity` extension files, run:

```sh
make USE_PGXS=1 check-claims oauth_conn_test
PGBIN="$(pg_config --bindir)" python3 test/identity_provisioning.py
PGBIN="$(pg_config --bindir)" python3 test/identity_worker_failures.py
```

The disposable Unix-socket-only server verifies first-login creation, individual
audit identity, read/write authorization, SUPERUSER downgrade, old-token replay,
empty-assignment revocation, collision rejection, concurrent logins, inherited
and overridden session settings, and unchanged SCRAM service authentication.
Tokens use ephemeral keys and synthetic Entra-shaped claims; this is not a live
tenant integration test. No existing server or service account is changed.
The second suite verifies transactional rollback, cancellation, authentication
timeouts, worker exhaustion and invalid management databases.

## Keycloak device flow

End-to-end test for pg_oidc_validator using Keycloak.

## Prerequisites

- PostgreSQL 18 with pg_oidc_validator installed
- Podman or Docker (Podman is preferred and automatically detected; Docker is used as fallback)
- Ruby with bundler
- Chrome/Chromium with chromedriver

## Setup

```bash
bundle install

# Trust the test SSL certificate (required for psql OAuth)
sudo cp keys/crt.pem /usr/local/share/ca-certificates/keycloak-test.crt
sudo update-ca-certificates
```

## Usage

```bash
# Run all tests
PGBIN=/path/to/postgres/bin bundle exec rspec

# Run specific test or with options
PGBIN=/path/to/postgres/bin bundle exec rspec spec/oauth_device_flow_spec.rb
bundle exec rspec --format documentation
```

## What it does

The Keycloak test covers a successful login through the device flow.

1. Sets up fresh PostgreSQL cluster with OAuth configuration
2. Starts Keycloak with pre-configured realm
3. Initiates psql OAuth device flow connection
4. Automatically completes authentication using Selenium
5. Verifies connection works

Auto-cleanup on exit.
