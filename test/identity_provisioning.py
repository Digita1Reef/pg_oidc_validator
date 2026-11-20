"""Exercise delegated OAuth provisioning against an isolated PostgreSQL server.

All tokens and credentials are synthetic. No existing database is contacted.
"""

import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hba_audience
from hba_audience import CLIENT, ENV, PGBIN, b64url, run_pg, signing_fixture


TENANT = "11111111-1111-4111-8111-111111111111"
OBJECT = "22222222-2222-4222-8222-222222222222"
USER = "developer@example.invalid"
AUDIENCE = "identity-test-resource"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


def token(key, claims):
    signed = b".".join(b64url(json.dumps(part).encode())
                       for part in ({"alg": "RS256", "kid": "test"}, claims))
    return (signed + b"." + b64url(key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))).decode()


def exercise(directory, discovery, key):
    data = directory / "pgdata"
    run_pg("initdb", "-D", data, "-U", "test_admin", "-A", "trust", "--no-locale", "-E", "UTF8")
    major = int((data / "PG_VERSION").read_text().strip())
    oauth = f'local all all oauth issuer="{ISSUER}" scope=connect delegate_ident_mapping=1'
    if major >= 19:
        oauth += f' validator.audience="{AUDIENCE}"'
    mapped_oauth = oauth.replace("local all all ", "local all legacy_user ").replace(" delegate_ident_mapping=1", "")
    (data / "pg_hba.conf").write_text(
        "local all test_admin trust\nlocal all service_app scram-sha-256\n" + mapped_oauth + "\n" + oauth + "\n")
    with (data / "postgresql.conf").open("a") as conf:
        conf.write(f"""
listen_addresses = ''
unix_socket_directories = '{directory}'
shared_preload_libraries = 'pg_oidc_validator'
oauth_validator_libraries = 'pg_oidc_validator'
pg_oidc_validator.discovery_url_override = '{discovery}'
pg_oidc_validator.audience = '{AUDIENCE}'
pg_oidc_validator.management_database = 'postgres'
pg_oidc_validator.identity_tenant = '{TENANT}'
max_worker_processes = 8
authentication_timeout = '15s'
idle_session_timeout = '90s'
""")
    logfile = directory / "postgres.log"
    try:
        run_pg("pg_ctl", "-D", data, "-l", logfile, "-w", "start")
    except subprocess.CalledProcessError as error:
        raise RuntimeError(logfile.read_text()) from error
    try:
        def admin(sql):
            return run_pg("psql", "-XAt", "-h", directory, "-U", "test_admin", "-d", "postgres",
                          "-v", "ON_ERROR_STOP=1", "-c", sql)

        def check(condition, message):
            if not condition:
                raise AssertionError(message)

        def login(claims, sql="SELECT current_user", expected=USER, requested=USER):
            connection = (f"host={directory} dbname=postgres user='{requested}' require_auth=oauth "
                          f"oauth_issuer={ISSUER} oauth_client_id=test")
            result = subprocess.run([CLIENT, connection, sql, token(key, claims)], env=ENV,
                                    text=True, capture_output=True, timeout=20)
            if expected is None:
                check(result.returncode != 0, "login/query unexpectedly succeeded")
            else:
                check(result.returncode == 0 and result.stdout.strip() == expected,
                      f"login/query failed: {result.stderr}; output={result.stdout}")
            return result

        check(admin("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL") == "0", "bad HBA")
        admin("CREATE EXTENSION pg_oidc_identity")
        run_pg("psql", "-XAt", "-h", directory, "-U", "test_admin", "-d", "postgres",
               "-v", "ON_ERROR_STOP=1", "-f", Path(__file__).with_name("identity_policy.sql"))
        print("SQL permission profiles, RLS, native settings and transactional expiry: PASS")
        admin(f"INSERT INTO oidc_identity.configuration VALUES (true, '{TENANT}')")
        admin("CREATE ROLE reader NOLOGIN; CREATE ROLE writer NOLOGIN; "
              "CREATE TABLE public.documents(id integer PRIMARY KEY, note text); "
              "INSERT INTO public.documents VALUES (1, 'original'); "
              "GRANT SELECT ON public.documents TO reader; "
              "GRANT SELECT,INSERT,UPDATE,DELETE ON public.documents TO writer")
        admin("INSERT INTO oidc_identity.entitlements(claim,sql_roles,superuser,settings) VALUES "
              "('Data.Read',ARRAY['reader']::name[],false,'{}'), "
              "('Data.Write',ARRAY['writer']::name[],false,'{\"idle_session_timeout\":\"30000ms\"}'), "
              "('Cluster.Admin','{}',true,'{}')")
        issued = int(time.time()) - 30
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "pairwise-subject", "scp": "connect", "ver": "2.0",
                  "tid": TENANT, "oid": OBJECT, "preferred_username": USER,
                  "iat": issued, "exp": int(time.time()) + 600, "roles": ["Data.Read"]}
        check(admin(f"SELECT count(*) FROM pg_roles WHERE rolname='{USER}'") == "0", "fixture collision")
        login(claims, "SELECT current_user,session_user,system_user",
              f"{USER}\t{USER}\toauth:{TENANT}:{OBJECT}")
        login(claims, "SELECT note FROM public.documents", "original")
        login(claims, "INSERT INTO public.documents VALUES (2,'denied'); SELECT 1", None)
        login(claims, "SELECT * FROM oidc_identity.identities", None)
        login(claims, "SELECT oidc_identity.reconcile('{}'::jsonb)", None)
        login(claims, "SHOW idle_session_timeout", "90s")
        print("First login provisions individual identity; read-only permissions and private registry verified")

        # Newer grants replace only managed membership and role settings.
        write = dict(claims, iat=issued + 1, roles=["Data.Write"])
        login(write, "INSERT INTO public.documents VALUES (2,'allowed'); SELECT count(*) FROM public.documents", "2")
        login(write, "SHOW idle_session_timeout", "30s")
        login(write, "SET ROLE writer; SELECT current_user", None)
        admin(f'ALTER ROLE "{USER}" SET application_name TO \'manual-setting\'')
        admin("UPDATE oidc_identity.entitlements SET settings='{}' WHERE claim='Data.Write'")
        login(write, "SHOW idle_session_timeout", "90s")
        login(write, "SHOW application_name", "manual-setting")
        print("Settings inherit cluster defaults, override, and reset without removing unrelated settings")

        elevated = dict(claims, iat=issued + 2, roles=["Cluster.Admin"])
        login(elevated, "SELECT rolsuper FROM pg_roles WHERE rolname=current_user", "t")
        downgraded = dict(claims, iat=issued + 3)
        login(downgraded, "SELECT rolsuper FROM pg_roles WHERE rolname=current_user", "f")
        login(elevated, expected=None)
        check(admin(f"SELECT rolsuper FROM pg_roles WHERE rolname='{USER}'") == "f", "stale token escalated")
        login(downgraded, "INSERT INTO public.documents VALUES (3,'denied'); SELECT 1", None)
        print("SUPERUSER downgrade and stale-token privilege restoration protection verified")

        # An empty assignment revokes managed access even though authentication denies.
        revoked = dict(claims, iat=issued + 4, roles=[])
        login(revoked, expected=None)
        check(admin(f"SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON m.member=r.oid "
                    f"WHERE r.rolname='{USER}'") == "0", "revoked identity retained managed roles")
        login(downgraded, expected=None)
        restored = dict(claims, iat=issued + 5)
        login(restored)
        print("Removed assignment denies login and removes managed privileges")

        for changed in ({"tid": "33333333-3333-4333-8333-333333333333"},
                        {"aud": "another-resource"}, {"roles": ["Unknown.Admin"]},
                        {"roles": "Data.Read"}, {"preferred_username": "someone@example.invalid"},
                        {"iat": int(time.time()) + 100}, {"exp": int(time.time()) - 10}):
            login(dict(restored, **changed), expected=None)
        login(dict(restored, oid="44444444-4444-4444-8444-444444444444"), expected=None)
        check(admin("SELECT count(*) FROM oidc_identity.identities") == "1", "rejected claims mutated registry")
        admin('CREATE ROLE "existing@example.invalid" LOGIN')
        collision = dict(restored, oid="55555555-5555-4555-8555-555555555555",
                         preferred_username="existing@example.invalid")
        login(collision, expected=None, requested="existing@example.invalid")
        print("Tenant, audience, expiry, identity mismatch and existing-role takeover rejected")

        # One stable identity survives a tenant username change; old token cannot revert it.
        renamed = dict(restored, iat=issued + 6, preferred_username="renamed@example.invalid")
        login(renamed, expected="renamed@example.invalid", requested="renamed@example.invalid")
        login(restored, expected=None)
        check(admin(f"SELECT count(*) FROM pg_roles WHERE rolname='{USER}'") == "0", "rename left duplicate role")
        login(dict(restored, oid="77777777-7777-4777-8777-777777777777"), expected=None)
        check(admin(f"SELECT count(*) FROM pg_roles WHERE rolname='{USER}'") == "0", "former name adopted")

        concurrent_name = "parallel@example.invalid"
        concurrent = dict(restored, oid="66666666-6666-4666-8666-666666666666",
                          preferred_username=concurrent_name)
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = [executor.submit(login, concurrent, expected=concurrent_name, requested=concurrent_name)
                       for _ in range(3)]
            for result in results:
                result.result()
        check(admin(f"SELECT count(*) FROM pg_roles WHERE rolname='{concurrent_name}'") == "1",
              "concurrent first login failed")
        print("Identity rename and concurrent first logins are consistent")

        # Ordinary service-account password authentication remains independent.
        admin("CREATE ROLE service_app LOGIN PASSWORD 'ephemeral-lab-password'")
        result = subprocess.run([str(PGBIN / "psql"), "-XAt", "-h", directory, "-d", "postgres",
                                 "-U", "service_app", "-c", "SELECT current_user"],
                                env=dict(ENV, PGPASSWORD="ephemeral-lab-password"),
                                text=True, capture_output=True, timeout=15)
        check(result.returncode == 0 and result.stdout.strip() == "service_app", "SCRAM regression")
        admin("CREATE ROLE legacy_user LOGIN")
        login(dict(claims, sub="legacy_user"), expected="legacy_user", requested="legacy_user")
        print(f"PostgreSQL {admin('SHOW server_version')} delegated identity integration: PASS")
    except Exception:
        # Logs contain only ephemeral lab identities, never a real tenant/token.
        print(logfile.read_text()[-18000:])
        raise
    finally:
        run_pg("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")


if __name__ == "__main__":
    hba_audience.ISSUER = ISSUER
    with tempfile.TemporaryDirectory(prefix="oidc-jit-", dir="/tmp") as tmp:
        root = Path(tmp)
        with signing_fixture(root / "issuer") as (url, signing_key):
            exercise(root, url, signing_key)
