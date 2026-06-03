const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const express = require('express');
const getExpressPath = require('../utility/getExpressPath');
const { getLogger, extractErrorLogData } = require('dbgate-tools');
const { getTokenSecret } = require('../auth/authCommon');
const handoffSessions = require('../utility/handoffSessions');

const logger = getLogger('handoff');

// Plugin packages where a read-only handoff is actually enforced server-side:
// postgres/mysql/sqlite open the DB session read-only, and mssql/duckdb advertise
// readOnlySessions:false so the app layer blocks write/script execution. Oracle
// advertises readOnlySessions:true but its driver does not honor isReadOnly, so a
// read-only handoff would NOT block writes — fail closed for it and any engine not
// verified here.
const READONLY_ENFORCED_PACKAGES = new Set([
  'dbgate-plugin-postgres',
  'dbgate-plugin-mysql',
  'dbgate-plugin-sqlite',
  'dbgate-plugin-mssql',
  'dbgate-plugin-duckdb',
]);

// Route prefixes a read-only DB-browse handoff session may reach in full. These
// controllers operate on the session connection/database and gate every action
// with testConnectionPermission + the read-only DB session, so writes are
// already blocked and scoped to the token's own conid/database.
const HANDOFF_ALLOWED_ROUTE_PREFIXES = [
  '/auth',
  '/server-connections',
  '/database-connections',
  '/sessions',
  '/metadata',
  '/stream',
  '/health',
  '/__health',
];

// Actions reachable under an allowed prefix that a read-only DB-browse session
// must NOT reach. Native backup/restore spawn external tools (pg_dump / psql /
// mysqldump / mysql) as separate processes using the session credentials; they
// bypass the read-only DB session entirely, so restore can write to the database
// and backup can write files into the server's storage directory. The read-only
// guarantee does not cover them, so deny them outright. Checked before the
// allowlist below.
const HANDOFF_DENIED_ROUTE_EXACT = [
  '/database-connections/native-backup',
  '/database-connections/native-backup-command',
  '/database-connections/native-restore',
  '/database-connections/native-restore-command',
];

// Mixed controllers: allow ONLY these specific read actions. Their other actions
// write to shared server storage/files with no handoff-aware permission check
// (connections/save writes the datastore; jsldata/save-text|save-rows write
// files; config/delete-settings and config/start-trial mutate server config;
// plugins/command runs ungated plugin code — install/uninstall/upgrade are
// already gated by plugins/install), so the controllers cannot be prefix-allowed.
const HANDOFF_ALLOWED_ROUTE_EXACT = [
  '/connections/list',
  '/connections/get',
  '/config/get',
  '/config/get-settings',
  '/config/platform-info',
  '/config/changelog',
  '/config/update-settings',
  '/plugins/script',
  '/plugins/installed',
  '/plugins/auth-types',
  '/plugins/info',
  '/plugins/search',
  '/jsldata/get-info',
  '/jsldata/get-rows',
  '/jsldata/exists',
  '/jsldata/stream-rows',
  '/jsldata/get-stats',
  '/jsldata/load-field-values',
  '/jsldata/extract-timeline-chart',
];

// Everything else (archive, scheduler, query-history, apps, cloud, team-files,
// rest-connections, uploads, files, the connections/jsldata write actions, and
// the /runners/data + /files/data static mounts) is blocked for handoff tokens.

function getHandoffSecret() {
  return process.env.DBGATE_HANDOFF_SECRET;
}

/**
 * Express middleware: for requests authenticated with a handoff token (carrying a
 * `conid` claim), allow only the route prefixes a read-only DB browse needs and
 * reject everything else. This closes the class of raw/unchecked routes that the
 * permission allowlist does not cover. No-op for non-handoff requests.
 */
function handoffRouteGuard(req, res, next) {
  const conid = req?.user?.conid ?? req?.auth?.conid;
  if (!conid) {
    return next();
  }
  // Deny dangerous actions that live under an otherwise-allowed prefix first.
  const denied = HANDOFF_DENIED_ROUTE_EXACT.some(action => req.path === getExpressPath(action));
  if (denied) {
    logger.warn({ path: req.path }, 'DBGM-00000 Blocked route for handoff session');
    return res.status(403).json({ error: 'Not allowed for handoff session' });
  }
  const allowedByPrefix = HANDOFF_ALLOWED_ROUTE_PREFIXES.some(prefix => {
    const full = getExpressPath(prefix);
    return req.path === full || req.path.startsWith(`${full}/`);
  });
  const allowedByExact = HANDOFF_ALLOWED_ROUTE_EXACT.some(action => req.path === getExpressPath(action));
  if (!allowedByPrefix && !allowedByExact) {
    logger.warn({ path: req.path }, 'DBGM-00000 Blocked route for handoff session');
    return res.status(403).json({ error: 'Not allowed for handoff session' });
  }
  return next();
}

/**
 * Verifies the HMAC-SHA256 + timestamp scheme:
 *   X-Handoff-Timestamp: <unix-ms>
 *   X-Handoff-Signature: hex( HMAC-SHA256(secret, timestamp + "." + rawBody) )
 * Returns { ok: true } or { ok: false, status, message }.
 */
function verifyHmac(req) {
  const secret = getHandoffSecret();
  if (!secret) {
    return { ok: false, status: 503, message: 'Handoff not configured' };
  }

  const timestamp = req.headers['x-handoff-timestamp'];
  const signature = req.headers['x-handoff-signature'];
  if (!timestamp || !signature) {
    return { ok: false, status: 401, message: 'Missing handoff authentication headers' };
  }

  const ts = parseInt(timestamp, 10);
  if (!Number.isFinite(ts)) {
    return { ok: false, status: 401, message: 'Invalid handoff timestamp' };
  }
  if (Math.abs(Date.now() - ts) > handoffSessions.getReplayWindowMs()) {
    return { ok: false, status: 401, message: 'Handoff timestamp outside allowed window' };
  }

  // HMAC must be computed over the exact bytes received (captured by bodyParser verify hook).
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body ?? {}));
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest('hex');

  const expectedBuf = Buffer.from(expected, 'hex');
  let providedBuf;
  try {
    providedBuf = Buffer.from(String(signature), 'hex');
  } catch (err) {
    return { ok: false, status: 401, message: 'Invalid handoff signature' };
  }
  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return { ok: false, status: 401, message: 'Invalid handoff signature' };
  }

  // Replay defense: reject a signature we have already accepted within the window.
  if (!handoffSessions.registerSignature(expected)) {
    return { ok: false, status: 401, message: 'Replayed handoff request' };
  }

  return { ok: true };
}

function handleHandoff(req, res) {
  const auth = verifyHmac(req);
  if (!auth.ok) {
    logger.warn({ status: auth.status }, 'DBGM-00000 Rejected handoff request');
    return res.status(auth.status).json({ error: auth.message });
  }

  const { label, engine, host, port, database, user, password, readonly, ttlSeconds } = req.body || {};

  if (!engine || !host || !database) {
    return res.status(400).json({ error: 'Missing required fields: engine, host, database' });
  }

  // Fail closed: only create a read-only session for engines whose driver
  // actually enforces it, so the read-only guarantee is never silently false.
  const isReadonly = readonly !== false;
  if (isReadonly) {
    const pkg = typeof engine === 'string' ? engine.split('@')[1] : null;
    if (!READONLY_ENFORCED_PACKAGES.has(pkg)) {
      return res.status(400).json({
        error: `Read-only handoff is not supported for engine "${engine}" (read-only is not enforced server-side). Supported: postgres, mysql, sqlite, mssql, duckdb.`,
      });
    }
  }

  let session;
  try {
    session = handoffSessions.createSession({
      label,
      engine,
      host,
      port,
      database,
      user,
      password,
      readonly: isReadonly, // default to read-only unless explicitly disabled
      ttlSeconds,
    });
  } catch (err) {
    logger.error(extractErrorLogData(err), 'DBGM-00000 Error creating handoff session');
    return res.status(503).json({ error: 'Could not create handoff session' });
  }

  // The access token carries only the session reference + scope, never the password.
  const ttlSecondsForToken = Math.max(1, Math.round((new Date(session.expiresAt).getTime() - Date.now()) / 1000));
  const accessToken = jwt.sign(
    {
      conid: session.conid,
      database,
      readonly: isReadonly,
    },
    getTokenSecret(),
    { expiresIn: ttlSecondsForToken }
  );

  logger.info({ conid: session.conid }, 'DBGM-00000 Created handoff session');

  return res.json({
    accessToken,
    conid: session.conid,
    expiresAt: session.expiresAt,
  });
}

function handleRevoke(req, res) {
  const auth = verifyHmac(req);
  if (!auth.ok) {
    return res.status(auth.status).json({ error: auth.message });
  }

  const { conid } = req.body || {};
  if (!conid) {
    return res.status(400).json({ error: 'Missing conid' });
  }

  handoffSessions.revokeSession(conid);
  logger.info({ conid }, 'DBGM-00000 Revoked handoff session');
  return res.status(204).end();
}

/**
 * Registers the server-to-server handoff routes. Called from the web/server
 * bootstrap only (handoff is not used in the Electron desktop build).
 *
 * Refuses to boot on dangerous misconfiguration so the fork can never run with
 * handoff enabled but authentication weakened.
 */
function registerHandoffRoutes(app) {
  const secret = getHandoffSecret();

  if (!secret) {
    logger.warn('DBGM-00000 DBGATE_HANDOFF_SECRET not set; handoff endpoints are disabled');
    return;
  }
  if (secret.length < 32) {
    throw new Error('DBGATE_HANDOFF_SECRET must be at least 32 characters');
  }
  if (process.env.SKIP_ALL_AUTH) {
    throw new Error('SKIP_ALL_AUTH must not be set when DBGATE_HANDOFF_SECRET is configured');
  }
  if (process.env.BASIC_AUTH) {
    // express-basic-auth is installed before the HMAC routes and the Bearer
    // middleware, so it would challenge /auth/handoff and the iframe's later
    // token-authenticated requests before the handoff flow runs.
    throw new Error('BASIC_AUTH must not be set when DBGATE_HANDOFF_SECRET is configured');
  }
  if (process.env.CONNECTIONS) {
    logger.warn(
      'DBGM-00000 CONNECTIONS is set alongside handoff; static connections should be unset for handoff-only deployments'
    );
  }

  const router = express.Router();
  router.post('/', handleHandoff);
  router.post('/revoke', handleRevoke);
  app.use(getExpressPath('/auth/handoff'), router);

  logger.info('DBGM-00000 Handoff endpoints registered at /auth/handoff and /auth/handoff/revoke');
}

module.exports = {
  registerHandoffRoutes,
  handoffRouteGuard,
};
