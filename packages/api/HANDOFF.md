# Handoff sessions (platform integration)

This fork supports **per-user, per-connection, isolated** database sessions pushed
to a single shared DbGate instance by a trusted platform backend. Each session is
scoped to exactly one connection (and may browse every database that connection
can reach). DbGate never reads secret stores or Kubernetes itself — the platform
resolves the connection (host + credentials) and pushes it server-to-server.

## Endpoints

Both are authenticated by **HMAC-SHA256 + timestamp** (not a Bearer token) and
should be reachable only from the platform (enforce with a network policy).

Signature scheme:

```
X-Handoff-Timestamp: <unix-ms>
X-Handoff-Signature: hex( HMAC-SHA256(DBGATE_HANDOFF_SECRET, timestamp + "." + rawBody) )
```

Requests with a timestamp older than 30s, a bad signature, or a replayed
signature (within the 30s window) are rejected with `401`.

### `POST /auth/handoff`

Body:

```jsonc
{
  "label": "Acme — production (read-only)",
  "engine": "postgres@dbgate-plugin-postgres",
  "host": "acme-db-ro.acme-ns.svc.cluster.local",
  "port": 5432,
  "database": "acme",     // optional: the database the iframe auto-opens; the
                          // session can browse ALL databases on this connection
  "user": "readonly_user",
  "password": "••••••",   // server-to-server only; never logged or persisted
  "readonly": true,        // defaults to true if omitted
  "ttlSeconds": 1800       // defaults to HANDOFF_DEFAULT_TTL_SECONDS (1800)
}
```

Response:

```jsonc
{ "accessToken": "<jwt>", "conid": "sess_...", "expiresAt": "2026-06-02T12:34:56Z" }
```

The connection (including the password) is stored only in process memory. The
access token carries `{ conid, database, readonly, exp }` — never the password.
Open the iframe at `https://dbgate.internal/?token=<accessToken>`.

**Scope is the connection, not a single database.** A handoff session is bound to
exactly one connection and may browse every database that connection's
credentials can reach; `database` only selects which one the iframe opens first.
Bound what's visible by giving the platform-resolved connection a DB user scoped
to just the databases that user should see (e.g. one DB role per tenant).

### `POST /auth/handoff/revoke`

Body `{ "conid": "sess_..." }`. Drops the session and kills its DB subprocess.
Idempotent. Returns `204`.

## Configuration

| Env var | Purpose |
|---|---|
| `DBGATE_HANDOFF_SECRET` | Shared secret (min 32 chars). When set, the handoff endpoints are enabled. |
| `HANDOFF_DEFAULT_TTL_SECONDS` | Default session TTL when the request omits `ttlSeconds`. Default `1800`. |
| `CONNECTIONS` | Leave **unset** for handoff-only deployments. |
| `SKIP_ALL_AUTH` | Must be **unset** — startup fails if it is set together with the handoff secret. |
| `BASIC_AUTH` | Must be **unset** — it is installed before the handoff/Bearer middleware and would challenge the flow; startup fails if set together with the handoff secret. |

## How isolation & read-only work

- **Scoping:** the access token's `conid` claim drives a **default-deny
  allowlist** (`authProvider.getCurrentPermissions`): `~*` denies everything,
  then only the session connection plus the DB browse/query surface
  (`dbops/*`, `widgets/database`, `widgets/opened-tabs`) are granted. Every
  other connection and all instance-admin surfaces (plugin install, settings
  changes, shell scripts, disk/file access, apps, archive write, admin) are
  denied. The session-opening path (`sessions/create`) also calls
  `testConnectionPermission`, and `checkCurrentConnectionPermission` is scoped
  to the token's `conid`, so isolation holds in both storage and non-storage
  modes. Tampering with the token fails signature verification.
- **Token delivery:** the browser holds the access token **in memory only**
  (never `localStorage`), so concurrent same-origin iframes stay isolated and
  nothing persists after the iframe closes. A hard iframe reload loses the
  token; the platform must re-open the iframe with a fresh `?token=`.
- **Read-only:** the session connection carries `isReadOnly: true`, which reuses
  DbGate's existing server-side enforcement (`connectUtility`). A read-only
  handoff is only accepted for engines that actually enforce it — postgres,
  mysql, sqlite (DB session opened read-only) and mssql, duckdb (app-layer
  write/script block). It is **rejected (400)** for engines that do not enforce
  it server-side (e.g. oracle, whose driver ignores `isReadOnly`), so the
  read-only guarantee is never silently false. For supported engines, writes are
  rejected by the database/driver — covering the raw SQL console and any API
  path, not just the UI.
- **Route surface:** a route guard (`handoffRouteGuard`) restricts handoff-token
  requests to the routes a read-only browse needs and 403s everything else. The
  DB controllers (auth, server-connections, database-connections, sessions,
  metadata) are allowed in full since every action is DB-scoped and
  permission-checked (writes blocked by the read-only session). The mixed
  controllers `connections`, `config`, `plugins` and `jsldata` are limited to
  specific **read** actions, because their other actions write shared server
  storage/files without a handoff-aware check (e.g. `connections/save`,
  `config/delete-settings`, `config/start-trial`, `jsldata/save-rows`,
  `plugins/command`). Write-capable or unchecked controllers and the
  `/runners/data` + `/files/data` static mounts are unreachable.
- **Lifetime:** the token `exp` is enforced on every request; a periodic sweep
  evicts expired sessions and kills their subprocess.

## Scaling

The session map is per-pod process memory (correct for a single replica). For
>1 replica, add sticky sessions or move the map to a shared store (e.g. Redis).
