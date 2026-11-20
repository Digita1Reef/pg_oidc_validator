"""Adversarial worker lifecycle tests in a disposable PostgreSQL cluster.

The real validator and worker process synthetic signed Entra claims. A test-only
reconcile function injects SQL failures and blocking after transactional effects.
No existing server, real token, or production identity is used.
"""

import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import hba_audience
from hba_audience import CLIENT, ENV, PGBIN, run_pg, signing_fixture
from identity_provisioning import AUDIENCE, ISSUER, TENANT, token


LOCK_ID = 78152031
WORKER_TYPE = "OAuth identity provisioning"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def eventually(predicate, message, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(message)


class Cluster:
    def __init__(self, directory, discovery, key):
        self.directory = directory
        self.data = directory / "pgdata"
        self.logfile = directory / "postgres.log"
        self.key = key
        self.children = []
        run_pg("initdb", "-D", self.data, "-U", "test_admin", "-A", "trust", "--no-locale", "-E", "UTF8")
        major = int((self.data / "PG_VERSION").read_text().strip())
        oauth = f'local all all oauth issuer="{ISSUER}" scope=connect delegate_ident_mapping=1'
        if major >= 19:
            oauth += f' validator.audience="{AUDIENCE}"'
        (self.data / "pg_hba.conf").write_text("local all test_admin trust\n" + oauth + "\n")
        with (self.data / "postgresql.conf").open("a") as conf:
            conf.write(f"""
listen_addresses = ''
unix_socket_directories = '{directory}'
shared_preload_libraries = 'pg_oidc_validator'
oauth_validator_libraries = 'pg_oidc_validator'
pg_oidc_validator.discovery_url_override = '{discovery}'
pg_oidc_validator.audience = '{AUDIENCE}'
pg_oidc_validator.management_database = 'postgres'
pg_oidc_validator.identity_tenant = '{TENANT}'
max_worker_processes = 1
max_parallel_workers = 0
max_logical_replication_workers = 0
authentication_timeout = '15s'
""")

    def __enter__(self):
        try:
            run_pg("pg_ctl", "-D", self.data, "-l", self.logfile, "-w", "start")
        except subprocess.CalledProcessError as error:
            raise RuntimeError(self.logfile.read_text()) from error
        try:
            self.install_stub()
        except Exception:
            run_pg("pg_ctl", "-D", self.data, "-m", "immediate", "-w", "stop")
            raise
        return self

    def __exit__(self, exc_type, *_):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
        run_pg("pg_ctl", "-D", self.data, "-m", "immediate", "-w", "stop")
        if exc_type is not None:
            # Log content is confined to synthetic identities and local fixtures.
            print(self.logfile.read_text()[-18000:])

    def admin_command(self, database="postgres"):
        return [str(PGBIN / "psql"), "-XAtq", "-h", str(self.directory), "-U", "test_admin", "-d", database,
                "-v", "ON_ERROR_STOP=1"]

    def admin(self, sql, database="postgres", succeeds=True):
        result = subprocess.run([*self.admin_command(database), "-c", sql], env=ENV,
                                text=True, capture_output=True, timeout=10)
        require((result.returncode == 0) == succeeds, f"Unexpected fixture SQL result: {result.stderr}")
        return result.stdout.strip()

    def install_stub(self, database="postgres"):
        # The production function is tested separately. These explicit failures
        # exercise rollback/commit and process lifecycle in the native bridge.
        self.admin(f"""
            CREATE SCHEMA oidc_identity;
            CREATE TABLE oidc_identity.effects(username text PRIMARY KEY);
            CREATE TABLE oidc_identity.behavior(mode text NOT NULL);
            INSERT INTO oidc_identity.behavior VALUES ('success');
            CREATE FUNCTION oidc_identity.reconcile(request jsonb) RETURNS boolean
            LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $body$
            DECLARE
                username text := request->>'username';
                behavior text;
            BEGIN
                SELECT mode INTO STRICT behavior FROM oidc_identity.behavior;
                EXECUTE format('CREATE ROLE %I LOGIN', username);
                INSERT INTO oidc_identity.effects VALUES (username);
                IF behavior = 'error' THEN
                    RAISE EXCEPTION 'synthetic reconciliation failure';
                ELSIF behavior = 'null' THEN
                    RETURN NULL;
                ELSIF behavior = 'block' THEN
                    PERFORM pg_advisory_xact_lock({LOCK_ID});
                END IF;
                RETURN behavior <> 'deny';
            END
            $body$;
            REVOKE ALL ON SCHEMA oidc_identity FROM PUBLIC;
            REVOKE ALL ON FUNCTION oidc_identity.reconcile(jsonb) FROM PUBLIC;
        """, database)

    def behavior(self, mode):
        require(mode in {"success", "error", "null", "block", "deny"}, "invalid fixture mode")
        self.admin(f"UPDATE oidc_identity.behavior SET mode='{mode}'")

    def setting(self, name, value):
        require(name in {"authentication_timeout", "pg_oidc_validator.management_database"}, "invalid fixture setting")
        self.admin(f"ALTER SYSTEM SET {name} = '{value}'")
        self.admin("SELECT pg_reload_conf()")
        eventually(lambda: self.admin(f"SHOW {name}") == value, "configuration was not reloaded")

    def spawn_login(self, username):
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "worker-test", "scp": "connect", "ver": "2.0",
                  "tid": TENANT, "oid": str(uuid.uuid4()), "preferred_username": username,
                  "iat": int(time.time()) - 10, "exp": int(time.time()) + 300, "roles": ["Data.Read"]}
        connection = (f"host={self.directory} dbname=postgres user='{username}' require_auth=oauth "
                      f"oauth_issuer={ISSUER} oauth_client_id=test")
        child = subprocess.Popen([CLIENT, connection, "SELECT current_user", token(self.key, claims)],
                                 env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def finish_login(self, child, username=None, timeout=20):
        stdout, stderr = child.communicate(timeout=timeout)
        if username is None:
            require(child.returncode != 0, "OAuth unexpectedly authorized a failing request")
        else:
            require(child.returncode == 0 and stdout.strip() == username,
                    f"Expected successful synthetic login: {stderr}")

    def workers(self):
        return int(self.admin(f"SELECT count(*) FROM pg_stat_activity WHERE backend_type='{WORKER_TYPE}'"))

    def blocked_worker(self):
        return self.admin(f"SELECT count(*) FROM pg_stat_activity WHERE backend_type='{WORKER_TYPE}' "
                          "AND wait_event_type='Lock' AND wait_event='advisory'") == "1"

    def no_workers(self):
        eventually(lambda: self.workers() == 0, "provisioning worker lingered after failed/finished authentication")

    def check_effects(self, username, present=False, database="postgres"):
        expected = "1" if present else "0"
        require(self.admin(f"SELECT count(*) FROM pg_roles WHERE rolname='{username}'") == expected,
                "unexpected role persistence after reconciliation")
        require(self.admin(f"SELECT count(*) FROM oidc_identity.effects WHERE username='{username}'", database) == expected,
                "unexpected reconciliation row persistence")

    def client_pids(self):
        output = self.admin("SELECT pid FROM pg_stat_activity WHERE backend_type='client backend' "
                            "AND pid <> pg_backend_pid() ORDER BY pid")
        return {int(pid) for pid in output.splitlines() if pid}

    @contextmanager
    def hold_lock(self):
        child = subprocess.Popen(self.admin_command(), env=ENV, text=True, stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.children.append(child)
        child.stdin.write(f"SELECT pg_advisory_lock({LOCK_ID});\n")
        child.stdin.flush()
        try:
            eventually(lambda: self.admin("SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
                                          f"AND objid={LOCK_ID} AND granted") == "1", "fixture lock was not acquired")
            yield
        finally:
            if child.poll() is None:
                child.communicate("\\q\n", timeout=5)


def exercise(cluster):
    cluster.finish_login(cluster.spawn_login("worker-ok@example.invalid"), "worker-ok@example.invalid")
    cluster.no_workers()
    cluster.check_effects("worker-ok@example.invalid", present=True)

    for mode in ("error", "null"):
        cluster.behavior(mode)
        username = f"worker-{mode}@example.invalid"
        cluster.finish_login(cluster.spawn_login(username))
        cluster.no_workers()
        cluster.check_effects(username)
    print("SQL errors and invalid NULL results roll back role/row effects")

    cluster.behavior("deny")
    username = "worker-deny@example.invalid"
    cluster.finish_login(cluster.spawn_login(username))
    cluster.no_workers()
    cluster.check_effects(username, present=True)
    print("Explicit false result commits its deliberate changes while denying login")

    cluster.behavior("block")
    with cluster.hold_lock():
        first_name = "worker-slot-holder@example.invalid"
        first = cluster.spawn_login(first_name)
        eventually(cluster.blocked_worker, "first worker did not reach its transactional blocker")
        second_name = "worker-slot-denied@example.invalid"
        cluster.finish_login(cluster.spawn_login(second_name), timeout=5)
        require(cluster.workers() == 1 and first.poll() is None, "exhaustion disturbed the active worker")
        cluster.check_effects(second_name)
    cluster.finish_login(first, first_name)
    cluster.no_workers()
    print("Exhausted worker slots fail closed without partial identity creation")

    with cluster.hold_lock():
        before = cluster.client_pids()
        username = "worker-cancel@example.invalid"
        child = cluster.spawn_login(username)
        eventually(cluster.blocked_worker, "cancel fixture did not reach its transactional blocker")
        added = cluster.client_pids() - before
        require(len(added) == 1, "could not uniquely identify the disposable authentication backend")
        parent_pid = next(iter(added))
        require(cluster.admin(f"SELECT pg_terminate_backend({parent_pid})") == "t", "authentication cancellation failed")
        cluster.finish_login(child, timeout=8)
        cluster.no_workers()
        cluster.check_effects(username)
    cluster.check_effects(username)
    print("Cancelled authentication terminates its worker and rolls back pending effects")

    cluster.setting("authentication_timeout", "3s")
    with cluster.hold_lock():
        username = "worker-timeout@example.invalid"
        child = cluster.spawn_login(username)
        eventually(cluster.blocked_worker, "timeout fixture did not reach its transactional blocker", timeout=2)
        cluster.finish_login(child, timeout=8)
        cluster.no_workers()
        cluster.check_effects(username)
    cluster.check_effects(username)
    cluster.setting("authentication_timeout", "15s")
    print("Authentication timeout terminates its worker and rolls back pending effects")

    cluster.setting("pg_oidc_validator.management_database", "missing_management")
    username = "worker-missing-db@example.invalid"
    cluster.finish_login(cluster.spawn_login(username))
    cluster.no_workers()
    cluster.check_effects(username)
    for template in ("template0", "template1"):
        cluster.admin(f"ALTER SYSTEM SET pg_oidc_validator.management_database='{template}'", succeeds=False)
        require(cluster.admin("SHOW pg_oidc_validator.management_database") == "missing_management",
                "invalid template setting silently replaced the live setting")

    cluster.admin("CREATE DATABASE marked_template")
    cluster.install_stub("marked_template")
    cluster.admin("ALTER DATABASE marked_template IS_TEMPLATE true")
    cluster.setting("pg_oidc_validator.management_database", "marked_template")
    username = "worker-template@example.invalid"
    cluster.finish_login(cluster.spawn_login(username))
    cluster.no_workers()
    cluster.check_effects(username, database="marked_template")
    print("Missing and template management databases reject provisioning")
    print(f"PostgreSQL {cluster.admin('SHOW server_version')} worker failure integration: PASS")


if __name__ == "__main__":
    hba_audience.ISSUER = ISSUER
    with tempfile.TemporaryDirectory(prefix="oidc-worker-", dir="/tmp") as temporary:
        root = Path(temporary)
        with signing_fixture(root / "issuer") as (discovery, key):
            with Cluster(root, discovery, key) as server:
                exercise(server)
