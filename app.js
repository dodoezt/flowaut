import { initVaultFeature, clearVaultState, showUnlockView, openForm } from './js/vault.js';
import { initAdminFeature, showAdminDashboard } from './js/admin.js';
import { showView } from './js/ui.js';

const APP_BASE = new URL('.', document.baseURI).pathname.replace(/\/$/, '');

function goHome(replace = false) {
  history[replace ? 'replaceState' : 'pushState']({}, '', `${APP_BASE}/`);
  route();
}

function route() {
  const routePath = location.pathname.slice(APP_BASE.length) || '/';
  if (/^\/admin\/?$/i.test(routePath)) {
    clearVaultState();
    showAdminDashboard();
    return;
  }

  const vaultMatch = routePath.match(/^\/vault\/([0-9a-f-]{36})\/?$/i);
  if (vaultMatch) {
    showUnlockView();
    return;
  }

  clearVaultState();
  showView('home');
}

initVaultFeature({ goHome });
initAdminFeature({ goHome });

document.querySelectorAll('[data-home]').forEach((element) => element.addEventListener('click', (event) => {
  event.preventDefault();
  goHome();
}));

document.querySelector('[data-admin]').addEventListener('click', (event) => {
  event.preventDefault();
  history.pushState({}, '', `${APP_BASE}/admin`);
  route();
});

window.addEventListener('popstate', route);
window.addEventListener('keydown', (event) => {
  const target = event.target;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) return;
  if (event.ctrlKey && event.key.toLowerCase() === 'm') {
    event.preventDefault();
    openForm('create');
  } else if (event.ctrlKey && event.key === 'Enter') {
    event.preventDefault();
    openForm('enter');
  }
});

route();
