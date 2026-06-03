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

export function setVolatileAccessToken(token) {
  volatileAccessToken = token;
}

export function getVolatileAccessToken() {
  return volatileAccessToken;
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
