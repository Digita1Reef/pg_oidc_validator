\echo Use "CREATE EXTENSION pg_oidc_identity" to load this file. \quit

-- The control file creates this schema if needed. Never adopt a populated or
-- untrusted existing namespace: the final ACL lockdown belongs only to us.
DO $$
DECLARE namespace_oid oid;
BEGIN
    SELECT n.oid INTO namespace_oid FROM pg_catalog.pg_namespace AS n
        JOIN pg_catalog.pg_roles AS r ON r.oid = n.nspowner
        WHERE n.nspname = 'oidc_identity' AND r.rolsuper;
    IF namespace_oid IS NULL THEN
        RAISE EXCEPTION 'oidc_identity schema must be owned by a superuser'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT FROM pg_catalog.pg_namespace AS n,
          pg_catalog.aclexplode(coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) AS a
        LEFT JOIN pg_catalog.pg_roles AS r ON r.oid = a.grantee
        WHERE n.oid = namespace_oid AND
          ((a.grantee = 0 AND a.privilege_type = 'CREATE')
           OR (a.grantee <> 0 AND NOT coalesce(r.rolsuper, false)))
    ) THEN
        RAISE EXCEPTION 'oidc_identity schema must not have untrusted grants'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT FROM pg_catalog.pg_depend AS d
        WHERE d.refclassid = 'pg_catalog.pg_namespace'::regclass AND d.refobjid = namespace_oid
          AND NOT (d.classid = 'pg_catalog.pg_extension'::regclass AND d.objid = coalesce(
              (SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'pg_oidc_identity'), 0))
    ) THEN
        RAISE EXCEPTION 'oidc_identity requires an empty dedicated schema'
            USING ERRCODE = '55000';
    END IF;
END
$$;

REVOKE ALL ON SCHEMA oidc_identity FROM PUBLIC;

-- Install the reconciliation registry in one management database per cluster.
-- Other databases may install this extension only to use configure_profile.
CREATE TABLE oidc_identity.configuration (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id uuid NOT NULL
);

CREATE TABLE oidc_identity.entitlements (
    claim text COLLATE "C" PRIMARY KEY CHECK (length(claim) BETWEEN 1 AND 120),
    sql_roles name[] NOT NULL DEFAULT '{}'::name[],
    owner_roles name[] NOT NULL DEFAULT '{}'::name[],
    superuser boolean NOT NULL DEFAULT false,
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (cardinality(sql_roles) > 0 OR superuser)
);

CREATE TABLE oidc_identity.identities (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    role_oid oid NOT NULL UNIQUE,
    username name NOT NULL UNIQUE,
    issued_at bigint NOT NULL,
    claims jsonb NOT NULL,
    PRIMARY KEY (tenant_id, object_id)
);

-- A PostgreSQL startup packet carries a name, not a role OID. Reserve every
-- former name permanently so a concurrent authentication cannot resolve a
-- recently renamed identity's old name to a different person's new role.
CREATE TABLE oidc_identity.identity_names (
    username name PRIMARY KEY,
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL
);

CREATE TABLE oidc_identity.managed_memberships (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    granted_role oid NOT NULL,
    grantor oid NOT NULL,
    PRIMARY KEY (tenant_id, object_id, granted_role),
    FOREIGN KEY (tenant_id, object_id)
        REFERENCES oidc_identity.identities ON DELETE CASCADE
);

CREATE TABLE oidc_identity.managed_settings (
    tenant_id uuid NOT NULL,
    object_id uuid NOT NULL,
    setting text NOT NULL,
    previous_value text,
    applied_value text NOT NULL,
    PRIMARY KEY (tenant_id, object_id, setting),
    FOREIGN KEY (tenant_id, object_id)
        REFERENCES oidc_identity.identities ON DELETE CASCADE
);

-- Records only profiles explicitly configured here; never infer ownership from
-- a role's name. Roles/ACLs are cluster objects; this catalogue is database local.
CREATE TABLE oidc_identity.profiles (
    role_oid oid PRIMARY KEY,
    profile text NOT NULL
);

CREATE FUNCTION oidc_identity.require_admin() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
        RAISE EXCEPTION 'oidc_identity requires a superuser administrator'
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE FUNCTION oidc_identity.validate_settings(settings_value jsonb) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE item record;
BEGIN
    IF jsonb_typeof(settings_value) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'settings must be a JSON object' USING ERRCODE = '22023';
    END IF;
    FOR item IN SELECT j.key, j.value AS val FROM jsonb_each(settings_value) AS j LOOP
        IF item.key NOT IN ('idle_session_timeout', 'idle_in_transaction_session_timeout',
                            'statement_timeout', 'lock_timeout', 'transaction_timeout')
           OR jsonb_typeof(item.val) <> 'string'
           OR (item.val #>> '{}') !~ '^(0|[1-9][0-9]*ms)$' THEN
            RAISE EXCEPTION 'unsupported setting or noncanonical timeout value'
                USING ERRCODE = '22023';
        END IF;
        IF length(item.val #>> '{}') > 12
           OR replace(item.val #>> '{}', 'ms', '')::numeric > 2147483647 THEN
            RAISE EXCEPTION 'timeout exceeds PostgreSQL millisecond range'
                USING ERRCODE = '22023';
        END IF;
    END LOOP;
END
$$;

CREATE FUNCTION oidc_identity.validate_entitlement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    PERFORM oidc_identity.require_admin();
    PERFORM oidc_identity.validate_settings(NEW.settings);
    IF EXISTS (
        SELECT FROM unnest(NEW.sql_roles) AS wanted(name)
        LEFT JOIN pg_roles AS r ON r.rolname = wanted.name
        WHERE r.oid IS NULL OR r.rolcanlogin OR r.rolsuper OR r.rolcreatedb
              OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'sql_roles must reference existing unprivileged NOLOGIN roles'
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (
        SELECT FROM unnest(NEW.owner_roles) AS wanted(name)
        LEFT JOIN pg_roles AS r ON r.rolname = wanted.name
        WHERE wanted.name IS NULL OR NOT wanted.name = ANY(NEW.sql_roles)
           OR NOT EXISTS (SELECT FROM pg_shdepend AS d
                          WHERE d.refclassid = 'pg_authid'::regclass
                            AND d.refobjid = r.oid AND d.deptype = 'o')
    ) THEN
        RAISE EXCEPTION 'owner_roles must be explicit sql_roles with existing ownership'
            USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER validate_entitlement BEFORE INSERT OR UPDATE
ON oidc_identity.entitlements FOR EACH ROW
EXECUTE FUNCTION oidc_identity.validate_entitlement();

CREATE FUNCTION oidc_identity.role_setting(role_id oid, setting_name text)
RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT substr(option, length(setting_name) + 2)
    FROM pg_db_role_setting, unnest(setconfig) AS option
    WHERE setdatabase = 0 AND setrole = role_id
      AND split_part(option, '=', 1) = setting_name
$$;

-- Called only by the trusted native worker, after cryptographic token checking.
-- A normal false return MUST be committed: empty claims revoke managed access.
-- Errors are transactional; no partial provisioning survives an exception.
CREATE FUNCTION oidc_identity.reconcile(request jsonb) RETURNS boolean
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    tid uuid;
    subject_id uuid;
    requested_name text;
    token_iat bigint;
    token_exp bigint;
    now_epoch numeric := extract(epoch FROM clock_timestamp());
    snapshot jsonb;
    identity_row oidc_identity.identities%ROWTYPE;
    known_identity boolean;
    live_role record;
    entitlement record;
    member_row record;
    setting_row record;
    item record;
    desired_roles oid[] := '{}'::oid[];
    desired_owners oid[] := '{}'::oid[];
    desired_settings jsonb := '{}'::jsonb;
    desired_superuser boolean := false;
    desired_name name;
    desired_oid oid;
    worker_oid oid;
    old_value text;
    original_value text;
BEGIN
    PERFORM oidc_identity.require_admin();
    IF jsonb_typeof(request) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(request)) <> 6
       OR NOT request ?& ARRAY['tenant_id','object_id','username','issued_at',
                               'expires_at','roles']
    THEN
        RAISE EXCEPTION 'invalid identity request fields' USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(request->'tenant_id') <> 'string'
       OR jsonb_typeof(request->'object_id') <> 'string'
       OR jsonb_typeof(request->'username') <> 'string'
       OR jsonb_typeof(request->'issued_at') <> 'number'
       OR jsonb_typeof(request->'expires_at') <> 'number'
       OR jsonb_typeof(request->'roles') <> 'array'
       OR (request->>'issued_at') !~ '^[0-9]{1,18}$'
       OR (request->>'expires_at') !~ '^[0-9]{1,18}$'
       OR EXISTS (SELECT FROM jsonb_array_elements(request->'roles') AS v
                  WHERE jsonb_typeof(v) <> 'string') THEN
        RAISE EXCEPTION 'invalid identity request types' USING ERRCODE = '22023';
    END IF;
    tid := (request->>'tenant_id')::uuid;
    subject_id := (request->>'object_id')::uuid;
    requested_name := request->>'username';
    token_iat := (request->>'issued_at')::bigint;
    token_exp := (request->>'expires_at')::bigint;
    IF octet_length(requested_name) NOT BETWEEN 1 AND 63
       OR requested_name LIKE 'pg\_%' ESCAPE '\'
       OR token_iat > now_epoch OR token_exp <= now_epoch OR token_exp <= token_iat THEN
        RETURN false;
    END IF;
    SELECT coalesce(jsonb_agg(value ORDER BY value), '[]'::jsonb) INTO snapshot
    FROM (SELECT DISTINCT value COLLATE "C" AS value
          FROM jsonb_array_elements_text(request->'roles')) AS claims;

    -- Stabilize policy while reconciling, then serialize first-login creation,
    -- rename, downgrade and concurrent stale-token requests for all identities.
    LOCK TABLE oidc_identity.configuration, oidc_identity.entitlements IN SHARE MODE;
    LOCK TABLE oidc_identity.identities IN SHARE ROW EXCLUSIVE MODE;
    now_epoch := extract(epoch FROM clock_timestamp());
    IF token_iat > now_epoch OR token_exp <= now_epoch THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (SELECT FROM oidc_identity.configuration WHERE tenant_id = tid) THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT FROM jsonb_array_elements_text(snapshot) AS claim(value)
               LEFT JOIN oidc_identity.entitlements AS e ON e.claim = claim.value
               WHERE e.claim IS NULL) THEN
        RETURN false;
    END IF;

    FOR entitlement IN SELECT e.* FROM oidc_identity.entitlements AS e
        JOIN jsonb_array_elements_text(snapshot) AS c(value) ON c.value = e.claim
        ORDER BY e.claim LOOP
        PERFORM oidc_identity.validate_settings(entitlement.settings);
        desired_superuser := desired_superuser OR entitlement.superuser;
        FOREACH desired_name IN ARRAY entitlement.sql_roles LOOP
            SELECT * INTO live_role FROM pg_roles WHERE rolname = desired_name;
            IF NOT FOUND OR live_role.rolcanlogin OR live_role.rolsuper
               OR live_role.rolcreatedb OR live_role.rolcreaterole
               OR live_role.rolreplication OR live_role.rolbypassrls THEN
                RETURN false;
            END IF;
            IF NOT live_role.oid = ANY(desired_roles) THEN
                desired_roles := array_append(desired_roles, live_role.oid);
            END IF;
            IF desired_name = ANY(entitlement.owner_roles) THEN
                IF NOT EXISTS (SELECT FROM pg_shdepend AS d
                               WHERE d.refclassid = 'pg_authid'::regclass
                                 AND d.refobjid = live_role.oid AND d.deptype = 'o') THEN
                    RETURN false;
                END IF;
                desired_owners := array_append(desired_owners, live_role.oid);
            END IF;
        END LOOP;
        FOR item IN SELECT key, value FROM jsonb_each(entitlement.settings) LOOP
            IF desired_settings ? item.key
               AND desired_settings->item.key <> item.value THEN
                RETURN false;
            END IF;
            desired_settings := desired_settings || jsonb_build_object(item.key, item.value);
        END LOOP;
    END LOOP;

    SELECT * INTO identity_row FROM oidc_identity.identities
        WHERE tenant_id = tid AND object_id = subject_id;
    known_identity := FOUND;
    IF known_identity THEN
        IF NOT EXISTS (SELECT FROM oidc_identity.identity_names AS n
                       WHERE n.username = identity_row.username
                         AND n.tenant_id = tid AND n.object_id = subject_id)
           OR EXISTS (SELECT FROM oidc_identity.identity_names AS n
                      WHERE n.username = requested_name
                        AND (n.tenant_id <> tid OR n.object_id <> subject_id)) THEN
            RETURN false;
        END IF;
        IF token_iat <= identity_row.issued_at
           AND (snapshot <> identity_row.claims OR requested_name <> identity_row.username::text) THEN
            RETURN false;
        END IF;
        SELECT * INTO live_role FROM pg_roles WHERE oid = identity_row.role_oid;
        IF NOT FOUND OR live_role.rolname <> identity_row.username THEN
            RETURN false;
        END IF;
        IF requested_name <> identity_row.username::text THEN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = requested_name) THEN
                RETURN false;
            END IF;
            EXECUTE format('ALTER ROLE %I RENAME TO %I', identity_row.username, requested_name);
            INSERT INTO oidc_identity.identity_names(username, tenant_id, object_id)
            VALUES (requested_name, tid, subject_id) ON CONFLICT (username) DO NOTHING;
        END IF;
    ELSE
        IF cardinality(desired_roles) = 0 AND NOT desired_superuser THEN
            RETURN false;
        END IF;
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = requested_name)
           OR EXISTS (SELECT FROM oidc_identity.identity_names WHERE username = requested_name) THEN
            RETURN false;
        END IF;
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB '
                       'NOCREATEROLE NOREPLICATION NOBYPASSRLS', requested_name);
        SELECT oid INTO identity_row.role_oid FROM pg_roles WHERE rolname = requested_name;
        INSERT INTO oidc_identity.identities
            (tenant_id, object_id, role_oid, username, issued_at, claims)
        VALUES (tid, subject_id, identity_row.role_oid, requested_name, token_iat, snapshot);
        INSERT INTO oidc_identity.identity_names(username, tenant_id, object_id)
        VALUES (requested_name, tid, subject_id);
    END IF;
    SELECT oid INTO worker_oid FROM pg_roles WHERE rolname = current_user;

    FOR member_row IN SELECT m.*, r.rolname, g.rolname AS grantor_name
        FROM oidc_identity.managed_memberships AS m
        LEFT JOIN pg_roles AS r ON r.oid = m.granted_role
        LEFT JOIN pg_roles AS g ON g.oid = m.grantor
        WHERE m.tenant_id = tid AND m.object_id = subject_id
          AND NOT m.granted_role = ANY(desired_roles) LOOP
        IF member_row.rolname IS NOT NULL AND member_row.grantor_name IS NOT NULL THEN
            EXECUTE format('REVOKE %I FROM %I GRANTED BY %I', member_row.rolname,
                           requested_name, member_row.grantor_name);
        END IF;
        DELETE FROM oidc_identity.managed_memberships
            WHERE tenant_id = tid AND object_id = subject_id
              AND granted_role = member_row.granted_role;
    END LOOP;
    FOREACH desired_oid IN ARRAY desired_roles LOOP
        SELECT rolname INTO desired_name FROM pg_roles WHERE oid = desired_oid;
        SELECT m.*, r.rolname AS grantor_name INTO member_row
        FROM oidc_identity.managed_memberships AS m
        JOIN pg_roles AS r ON r.oid = m.grantor
        WHERE m.tenant_id = tid AND m.object_id = subject_id AND m.granted_role = desired_oid;
        IF FOUND THEN
            EXECUTE format('GRANT %I TO %I WITH INHERIT TRUE, SET %s, ADMIN FALSE '
                           'GRANTED BY %I', desired_name, requested_name,
                           CASE WHEN desired_oid = ANY(desired_owners) THEN 'TRUE' ELSE 'FALSE' END,
                           member_row.grantor_name);
        ELSIF NOT EXISTS (SELECT FROM pg_auth_members WHERE roleid = desired_oid
                         AND member = identity_row.role_oid) THEN
            EXECUTE format('GRANT %I TO %I WITH INHERIT TRUE, SET %s, ADMIN FALSE '
                           'GRANTED BY %I', desired_name, requested_name,
                           CASE WHEN desired_oid = ANY(desired_owners) THEN 'TRUE' ELSE 'FALSE' END,
                           current_user);
            INSERT INTO oidc_identity.managed_memberships
                (tenant_id, object_id, granted_role, grantor)
            VALUES (tid, subject_id, desired_oid, worker_oid)
            ON CONFLICT (tenant_id, object_id, granted_role) DO UPDATE
                SET grantor = EXCLUDED.grantor;
        END IF;
    END LOOP;
    EXECUTE format('ALTER ROLE %I %s', requested_name,
                   CASE WHEN desired_superuser THEN 'SUPERUSER' ELSE 'NOSUPERUSER' END);

    FOR setting_row IN SELECT * FROM oidc_identity.managed_settings
        WHERE tenant_id = tid AND object_id = subject_id
          AND NOT desired_settings ? setting LOOP
        old_value := oidc_identity.role_setting(identity_row.role_oid, setting_row.setting);
        -- Preserve an out-of-band administrator override made after our write.
        IF old_value IS NOT DISTINCT FROM setting_row.applied_value THEN
            IF setting_row.previous_value IS NULL THEN
                EXECUTE format('ALTER ROLE %I RESET %I', requested_name, setting_row.setting);
            ELSE
                EXECUTE format('ALTER ROLE %I SET %I TO %L', requested_name,
                               setting_row.setting, setting_row.previous_value);
            END IF;
        END IF;
        DELETE FROM oidc_identity.managed_settings
            WHERE tenant_id = tid AND object_id = subject_id AND setting = setting_row.setting;
    END LOOP;
    FOR item IN SELECT key, value FROM jsonb_each_text(desired_settings) LOOP
        old_value := oidc_identity.role_setting(identity_row.role_oid, item.key);
        SELECT * INTO setting_row FROM oidc_identity.managed_settings
            WHERE tenant_id = tid AND object_id = subject_id AND setting = item.key;
        original_value := CASE WHEN FOUND AND old_value IS NOT DISTINCT FROM setting_row.applied_value
                               THEN setting_row.previous_value ELSE old_value END;
        EXECUTE format('ALTER ROLE %I SET %I TO %L', requested_name, item.key, item.value);
        INSERT INTO oidc_identity.managed_settings
            (tenant_id, object_id, setting, previous_value, applied_value)
        VALUES (tid, subject_id, item.key, original_value,
                oidc_identity.role_setting(identity_row.role_oid, item.key))
        ON CONFLICT (tenant_id, object_id, setting) DO UPDATE
            SET previous_value = EXCLUDED.previous_value, applied_value = EXCLUDED.applied_value;
    END LOOP;
    UPDATE oidc_identity.identities
        SET username = requested_name, issued_at = greatest(issued_at, token_iat), claims = snapshot
        WHERE tenant_id = tid AND object_id = subject_id;
    IF token_exp <= extract(epoch FROM clock_timestamp()) THEN
        -- An error, not a false result: roll back grants made by an expired token.
        RAISE EXCEPTION 'token expired during identity reconciliation' USING ERRCODE = '28000';
    END IF;
    RETURN cardinality(desired_roles) > 0 OR desired_superuser;
END
$$;

-- Administrator-only, additive profile provisioning in the target database.
-- Existing/PUBLIC/transitive privileges are not removed. EXECUTE is an explicit
-- routine list (no future-routine wildcard). OWNER transfers only named resources;
-- its database flag is separate because database ownership permits DROP DATABASE.
CREATE FUNCTION oidc_identity.configure_profile(
    role_name name,
    profile_name text,
    schemas name[] DEFAULT '{}'::name[],
    creators name[] DEFAULT '{}'::name[],
    routines regprocedure[] DEFAULT '{}'::regprocedure[],
    own_database boolean DEFAULT false,
    owned_relations regclass[] DEFAULT '{}'::regclass[]
) RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    target_role record;
    schema_name name;
    creator_name name;
    object_row record;
    routine_id regprocedure;
    relation_id regclass;
    relation_keyword text;
    table_privileges text;
    sequence_privileges text;
BEGIN
    PERFORM oidc_identity.require_admin();
    IF role_name IS NULL OR role_name::text = '' OR role_name::text LIKE 'pg\_%' ESCAPE '\'
       OR profile_name IS NULL OR profile_name NOT IN
          ('READ_ONLY','READ_WRITE','EXECUTE','MAINTAIN','OWNER',
           'CLUSTER.MONITOR','CLUSTER.SESSION_OPERATOR')
       OR schemas IS NULL OR creators IS NULL OR routines IS NULL
       OR owned_relations IS NULL OR own_database IS NULL THEN
        RAISE EXCEPTION 'invalid profile parameters; SUPERUSER uses the entitlement flag'
            USING ERRCODE = '22023';
    END IF;
    IF profile_name LIKE 'CLUSTER.%' AND
       (cardinality(schemas) <> 0 OR cardinality(creators) <> 0 OR cardinality(routines) <> 0
        OR cardinality(owned_relations) <> 0 OR own_database) THEN
        RAISE EXCEPTION 'cluster profiles do not accept database resources' USING ERRCODE = '22023';
    END IF;
    IF profile_name <> 'OWNER' AND (own_database OR cardinality(owned_relations) > 0)
       OR profile_name NOT IN ('OWNER','EXECUTE') AND cardinality(routines) > 0
       OR profile_name NOT IN ('READ_ONLY','READ_WRITE','MAINTAIN') AND cardinality(creators) > 0
       OR profile_name = 'EXECUTE' AND cardinality(routines) = 0
       OR profile_name NOT LIKE 'CLUSTER.%' AND cardinality(schemas) = 0
          AND NOT (profile_name = 'OWNER' AND own_database) THEN
        RAISE EXCEPTION 'profile resources must be explicit and applicable' USING ERRCODE = '22023';
    END IF;
    FOREACH schema_name IN ARRAY schemas LOOP
        IF schema_name IS NULL OR schema_name::text LIKE 'pg\_%' ESCAPE '\'
           OR schema_name IN ('information_schema','oidc_identity')
           OR NOT EXISTS (SELECT FROM pg_namespace WHERE nspname = schema_name) THEN
            RAISE EXCEPTION 'profile requires an existing application schema' USING ERRCODE = '22023';
        END IF;
    END LOOP;
    FOREACH creator_name IN ARRAY creators LOOP
        IF creator_name IS NULL OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = creator_name) THEN
            RAISE EXCEPTION 'default-privilege creator does not exist' USING ERRCODE = '22023';
        END IF;
    END LOOP;
    FOREACH routine_id IN ARRAY routines LOOP
        IF routine_id IS NULL OR NOT EXISTS (
            SELECT FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
            WHERE p.oid = routine_id AND n.nspname = ANY(schemas) AND p.prokind IN ('f','p','w')
        ) THEN
            RAISE EXCEPTION 'routine must exist in an explicitly supplied application schema'
                USING ERRCODE = '22023';
        END IF;
    END LOOP;
    FOREACH relation_id IN ARRAY owned_relations LOOP
        IF relation_id IS NULL OR NOT EXISTS (
            SELECT FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE c.oid = relation_id AND n.nspname = ANY(schemas)
              AND c.relkind IN ('r','p','v','m','S','f')
        ) THEN
            RAISE EXCEPTION 'owned relation must exist in an explicitly supplied application schema'
                USING ERRCODE = '22023';
        END IF;
    END LOOP;
    LOCK TABLE oidc_identity.profiles IN SHARE ROW EXCLUSIVE MODE;
    SELECT * INTO target_role FROM pg_roles WHERE rolname = role_name;
    IF NOT FOUND THEN
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                       'NOREPLICATION NOBYPASSRLS', role_name);
        SELECT * INTO target_role FROM pg_roles WHERE rolname = role_name;
    END IF;
    IF target_role.rolcanlogin OR target_role.rolsuper OR target_role.rolcreatedb
       OR target_role.rolcreaterole OR target_role.rolreplication OR target_role.rolbypassrls THEN
        RAISE EXCEPTION 'profile role must be an unprivileged NOLOGIN role' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT FROM oidc_identity.profiles
               WHERE role_oid = target_role.oid AND profile <> profile_name) THEN
        RAISE EXCEPTION 'profile role already has a different profile' USING ERRCODE = '22023';
    END IF;
    INSERT INTO oidc_identity.profiles(role_oid, profile) VALUES (target_role.oid, profile_name)
        ON CONFLICT (role_oid) DO NOTHING;

    IF profile_name = 'CLUSTER.MONITOR' THEN
        EXECUTE format('GRANT pg_monitor TO %I WITH INHERIT TRUE, SET FALSE, ADMIN FALSE', role_name);
        RETURN;
    ELSIF profile_name = 'CLUSTER.SESSION_OPERATOR' THEN
        EXECUTE format('GRANT pg_signal_backend TO %I WITH INHERIT TRUE, SET FALSE, ADMIN FALSE', role_name);
        RETURN;
    END IF;
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name);
    FOREACH schema_name IN ARRAY schemas LOOP
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, role_name);
        IF profile_name IN ('READ_ONLY','READ_WRITE','MAINTAIN') THEN
            table_privileges := CASE profile_name WHEN 'READ_ONLY' THEN 'SELECT'
                WHEN 'READ_WRITE' THEN 'SELECT, INSERT, UPDATE, DELETE' ELSE 'MAINTAIN' END;
            EXECUTE format('GRANT %s ON ALL TABLES IN SCHEMA %I TO %I',
                           table_privileges, schema_name, role_name);
            FOREACH creator_name IN ARRAY creators LOOP
                EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
                               'GRANT %s ON TABLES TO %I', creator_name, schema_name,
                               table_privileges, role_name);
            END LOOP;
        END IF;
        IF profile_name IN ('READ_ONLY','READ_WRITE') THEN
            sequence_privileges := CASE profile_name WHEN 'READ_ONLY' THEN 'SELECT'
                                                     ELSE 'SELECT, USAGE' END;
            EXECUTE format('GRANT %s ON ALL SEQUENCES IN SCHEMA %I TO %I',
                           sequence_privileges, schema_name, role_name);
            FOREACH creator_name IN ARRAY creators LOOP
                EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
                               'GRANT %s ON SEQUENCES TO %I', creator_name, schema_name,
                               sequence_privileges, role_name);
            END LOOP;
        ELSIF profile_name = 'OWNER' THEN
            EXECUTE format('ALTER SCHEMA %I OWNER TO %I', schema_name, role_name);
        END IF;
    END LOOP;
    IF profile_name = 'EXECUTE' THEN
        FOREACH routine_id IN ARRAY routines LOOP
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO %I', routine_id, role_name);
        END LOOP;
    ELSIF profile_name = 'OWNER' THEN
        IF own_database THEN
            EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), role_name);
        END IF;
        FOREACH relation_id IN ARRAY owned_relations LOOP
            SELECT relkind INTO object_row FROM pg_class WHERE oid = relation_id;
            relation_keyword := CASE object_row.relkind
                WHEN 'r' THEN 'TABLE' WHEN 'p' THEN 'TABLE' WHEN 'v' THEN 'VIEW'
                WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE'
                WHEN 'f' THEN 'FOREIGN TABLE' END;
            EXECUTE format('ALTER %s %s OWNER TO %I', relation_keyword, relation_id, role_name);
        END LOOP;
        FOREACH routine_id IN ARRAY routines LOOP
            EXECUTE format('ALTER ROUTINE %s OWNER TO %I', routine_id, role_name);
        END LOOP;
    END IF;
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA oidc_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA oidc_identity FROM PUBLIC;
