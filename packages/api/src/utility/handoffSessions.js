const crypto = require('crypto');
const { getLogger, extractErrorLogData } = require('dbgate-tools');

const logger = getLogger('handoffSessions');

// Default session lifetime (30 minutes) if the request omits ttlSeconds and
// HANDOFF_DEFAULT_TTL_SECONDS is not configured.
const FALLBACK_TTL_SECONDS = 1800;

// Requests must carry a timestamp within this window; signatures are remembered
// for the same window to reject replays.
const REPLAY_WINDOW_MS = 30 * 1000;

const SWEEP_INTERVAL_MS = 30 * 1000;

// conid -> { connection, expiresAt }   (process memory only, never persisted)
const sessions = new Map();

// hex signature -> first-seen timestamp (ms), for replay defense
const seenSignatures = new Map();

let sweepTimer = null;

function getDefaultTtlSeconds() {
  const raw = parseInt(process.env.HANDOFF_DEFAULT_TTL_SECONDS, 10);
  return Number.isFinite(raw) && raw > 0 ? raw : FALLBACK_TTL_SECONDS;
}

function getReplayWindowMs() {
  return REPLAY_WINDOW_MS;
}

/**
 * Build the in-memory connection definition for a handoff session.
 * The password lives only here and is sent to the DB subprocess in memory;
 * it is never persisted and never returned to the browser.
 */
function createSession({ label, engine, host, port, database, user, password, readonly, ttlSeconds }) {
  const conid = `sess_${crypto.randomBytes(16).toString('hex')}`;
  const ttl = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : getDefaultTtlSeconds();
  const expiresAt = Date.now() + ttl * 1000;

  const connection = {
    _id: conid,
    displayName: label,
    engine,
    server: host,
    port: port != null ? `${port}` : undefined,
    user,
    password,
    // The handoff scope is the whole connection: every database on it is
    // browsable (bounded by the connection's own DB credentials). `database`, if
    // given, is only a default to auto-open — not a hard scope. So the connection
    // is NOT singleDatabase; it lists all its databases like a normal connection.
    defaultDatabase: database || undefined,
    // Reuses DbGate's built-in server-side read-only enforcement (connectUtility
    // + read-only DB session for engines that support it). See connectUtility.js.
    isReadOnly: !!readonly,
    // Marker so other code can recognize a handoff-scoped connection.
    isHandoffSession: true,
  };

  sessions.set(conid, { connection, expiresAt });
  ensureSweeper();

  return { conid, expiresAt: new Date(expiresAt).toISOString() };
}

/**
 * Handoff scope is the connection, not a single database: a handoff session may
 * open any database reachable by the connection's credentials. Connection-level
 * isolation (one session = one connection) is enforced by testConnectionPermission
 * / checkCurrentConnectionPermission on the conid. Kept as a no-op so the existing
 * call sites stay in place if per-database scoping is ever reintroduced.
 */
function assertDatabaseInScope(connection, database) {
  // intentionally no per-database restriction; see doc comment above
}

function getSessionEntry(conid) {
  if (!conid) return null;
  const entry = sessions.get(conid);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    sessions.delete(conid);
    killConnectionSubprocess(conid);
    return null;
  }
  return entry;
}

/** Returns the in-memory connection def for a live session, or null if missing/expired. */
function getConnection(conid) {
  const entry = getSessionEntry(conid);
  return entry ? entry.connection : null;
}

function hasSession(conid) {
  return getSessionEntry(conid) != null;
}

/** Idempotent: removes the session and kills its DB subprocess. Returns true if it existed. */
function revokeSession(conid) {
  const existed = sessions.delete(conid);
  killConnectionSubprocess(conid);
  return existed;
}

/**
 * Records a signature within the replay window. Returns false if the signature
 * was already seen (replay), true otherwise.
 */
function registerSignature(signature) {
  if (!signature) return false;
  if (seenSignatures.has(signature)) {
    return false;
  }
  seenSignatures.set(signature, Date.now());
  return true;
}

function killConnectionSubprocess(conid) {
  // Lazy require to avoid circular dependencies at module load time.
  try {
    const serverConnections = require('../controllers/serverConnections');
    if (typeof serverConnections.close === 'function') {
      serverConnections.close(conid);
    }
  } catch (err) {
    logger.error(extractErrorLogData(err), 'DBGM-00000 Error closing server connection for handoff session');
  }
  try {
    const databaseConnections = require('../controllers/databaseConnections');
    if (typeof databaseConnections.closeAll === 'function') {
      databaseConnections.closeAll(conid);
    }
  } catch (err) {
    logger.error(extractErrorLogData(err), 'DBGM-00000 Error closing database connection for handoff session');
  }
  try {
    const sessions = require('../controllers/sessions');
    if (typeof sessions.closeForConid === 'function') {
      sessions.closeForConid(conid);
    }
  } catch (err) {
    logger.error(extractErrorLogData(err), 'DBGM-00000 Error closing SQL sessions for handoff session');
  }
}

function sweep() {
  const now = Date.now();
  for (const [conid, entry] of sessions) {
    if (now > entry.expiresAt) {
      sessions.delete(conid);
      killConnectionSubprocess(conid);
      logger.info({ conid }, 'DBGM-00000 Evicted expired handoff session');
    }
  }
  for (const [signature, ts] of seenSignatures) {
    if (now - ts > REPLAY_WINDOW_MS) {
      seenSignatures.delete(signature);
    }
  }
}

function ensureSweeper() {
  if (sweepTimer) return;
  sweepTimer = setInterval(sweep, SWEEP_INTERVAL_MS);
  // Don't keep the process alive solely for the sweeper.
  if (typeof sweepTimer.unref === 'function') {
    sweepTimer.unref();
  }
}

module.exports = {
  createSession,
  getConnection,
  hasSession,
  revokeSession,
  registerSignature,
  getDefaultTtlSeconds,
  getReplayWindowMs,
  assertDatabaseInScope,
  // exposed for tests
  _sweep: sweep,
};
