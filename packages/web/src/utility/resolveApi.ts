import getElectron from './getElectron';
import { isAdminPage, isOneOfPage } from './pageDefs';

let apiUrl = null;
try {
  apiUrl = process.env.API_URL;
} catch {}

export default function resolveApi() {
  if (apiUrl) {
    return apiUrl;
  }
  return (window.location.origin + window.location.pathname).replace(/\/[a-zA-Z-]+\.html$/, '').replace(/\/*$/, '');
}

// Handoff tokens are kept in memory only (never persisted), so concurrent
// same-origin iframes don't clobber each other via shared localStorage and no
// token is left behind after the iframe closes.
let volatileAccessToken = null;

// Sticky flag: once we've seen we're in a handoff session it stays true for the
// page lifetime. It can be detected before setVolatileAccessToken runs, because
// the platform opens the iframe with ?token=... and that param is present in the
// URL until handleOauthCallback() strips it — which happens after the stores
// module has already initialized. Reading the URL here lets persisted stores opt
// out of storage at construction time.
let handoffSessionDetected = false;

export function setVolatileAccessToken(token) {
  volatileAccessToken = token;
  if (token) {
    handoffSessionDetected = true;
  }
}

export function getVolatileAccessToken() {
  return volatileAccessToken;
}

// True when the page is running as a platform handoff session. Used to make the
// workspace ephemeral: a handoff session must not read or write persisted tab /
// connection state, both to stay isolated from other same-origin sessions and to
// avoid restoring tabs that point at a previous session's now-dead connection.
export function isHandoffSession() {
  if (handoffSessionDetected || volatileAccessToken) {
    return true;
  }
  try {
    if (typeof location !== 'undefined' && new URLSearchParams(location.search).get('token')) {
      handoffSessionDetected = true;
      return true;
    }
  } catch {
    // location not available (non-browser) — not a handoff session.
  }
  return false;
}

export function resolveApiHeaders() {
  const electron = getElectron();

  const res = {};
  const isAdmin = isOneOfPage('admin', 'admin-license');
  const accessToken =
    (!isAdmin && volatileAccessToken) || localStorage.getItem(isAdmin ? 'adminAccessToken' : 'accessToken');
  if (accessToken) {
    res['Authorization'] = `Bearer ${accessToken}`;
  }
  // if (isAdminPage()) {
  //   res['x-is-admin-page'] = 'true';
  // }
  return res;
}
