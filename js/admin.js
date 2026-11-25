import { api, apiUrl, setCsrfToken } from './api.js';
import { deriveKey, decryptText, decryptBytes } from './crypto.js';
import { showView, showError } from './ui.js';

const state = { vaults: [], selectedVault: null };

function renderVaults() {
  const target = document.querySelector('#admin-vaults');
  target.replaceChildren();
  document.querySelector('#admin-vault-count').textContent = String(state.vaults.length);
  if (!state.vaults.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No encrypted vaults have been created yet.';
    target.append(empty);
    return;
  }
  for (const vault of state.vaults) {
    const card = document.createElement('article');
    card.className = 'content-card admin-vault-row';
    const details = document.createElement('div');
    const title = document.createElement('h2');
    title.textContent = vault.name;
    const meta = document.createElement('div');
    meta.className = 'admin-vault-meta';
    meta.textContent = `Encrypted ${new Date(vault.created_at).toLocaleString()} · ${vault.note_count} notes · ${vault.file_count} files · ${(Number(vault.total_bytes) / 1048576).toFixed(2)} MB`;
    details.append(title, meta);
    const inspect = document.createElement('button');
    inspect.className = 'button primary';
    inspect.type = 'button';
    inspect.textContent = 'Inspect vault';
    inspect.addEventListener('click', () => openInspector(vault));
    card.append(details, inspect);
    target.append(card);
  }
}

async function loadVaults() {
  showError(document.querySelector('#admin-error'));
  try {
    const result = await api('/api/admin/vaults');
    state.vaults = result.vaults;
    renderVaults();
  } catch (error) {
    showError(document.querySelector('#admin-error'), error.message || 'Could not load vaults.');
  }
}

function openInspector(vault) {
  state.selectedVault = vault;
  document.querySelector('#admin-inspector-title').textContent = vault.name;
  document.querySelector('#admin-inspector').hidden = false;
  document.querySelector('#admin-decrypted').replaceChildren();
  document.querySelector('#admin-decrypted').hidden = true;
  document.querySelector('#admin-vault-password').value = '';
  showError(document.querySelector('#admin-unlock-error'));
  document.querySelector('#admin-inspector').scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelector('#admin-vault-password').focus();
}

async function handleUnlock(event) {
  event.preventDefault();
  const submit = event.currentTarget.querySelector('button[type="submit"]');
  const password = document.querySelector('#admin-vault-password').value;
  const errorElement = document.querySelector('#admin-unlock-error');
  submit.disabled = true;
  showError(errorElement);
  try {
    const result = await api(`/api/admin/vaults/${state.selectedVault.id}/unlock`, {
      method: 'POST', body: JSON.stringify({ password }),
    });
    const key = await deriveKey(password, result.vault.salt);
    const target = document.querySelector('#admin-decrypted');
    target.replaceChildren();
    if (!result.contents.length && !result.files.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'This vault has no notes or files.';
      target.append(empty);
    }
    for (const record of result.contents) {
      const card = document.createElement('article');
      card.className = 'content-card';
      const body = document.createElement('pre');
      body.className = 'content-text';
      body.textContent = await decryptText(record, key);
      const meta = document.createElement('div');
      meta.className = 'content-meta';
      meta.textContent = `Saved ${new Date(record.updated_at || record.created_at).toLocaleString()}`;
      card.append(body, meta);
      target.append(card);
    }
    for (const file of result.files) target.append(await makeFileRow(file, result.vault.id, key, errorElement));
    target.hidden = false;
  } catch (error) {
    showError(errorElement, error.message || 'Could not decrypt this vault. Check the password.');
  } finally {
    submit.disabled = false;
  }
}

async function makeFileRow(file, vaultId, key, errorElement) {
  const name = await decryptText({ ciphertext: file.encrypted_name, iv: file.name_iv }, key);
  const row = document.createElement('article');
  row.className = 'content-card decrypted-file';
  const label = document.createElement('span');
  label.textContent = `${name} · ${(Number(file.byte_size) / 1048576).toFixed(2)} MB`;
  const download = document.createElement('button');
  download.className = 'small-button';
  download.type = 'button';
  download.textContent = 'Decrypt & download';
  download.addEventListener('click', async () => {
    download.disabled = true;
    try {
      const response = await fetch(apiUrl(`/api/admin/vaults/${vaultId}/files/${file.id}`), { credentials: 'same-origin' });
      if (!response.ok) throw new Error('Could not download encrypted file.');
      const clear = await decryptBytes(await response.arrayBuffer(), file.file_iv, key);
      const objectUrl = URL.createObjectURL(new Blob([clear]));
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = name;
      link.click();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (error) {
      showError(errorElement, error.message || 'Could not decrypt file.');
    } finally {
      download.disabled = false;
    }
  });
  row.append(label, download);
  return row;
}

export async function showAdminDashboard() {
  showView('admin');
  document.querySelector('#admin-login').hidden = false;
  document.querySelector('#admin-dashboard').hidden = true;
  showError(document.querySelector('#admin-login-error'));
  try {
    const session = await api('/api/admin/session');
    if (session.authenticated) {
      setCsrfToken(session.csrfToken);
      document.querySelector('#admin-login').hidden = true;
      document.querySelector('#admin-dashboard').hidden = false;
      await loadVaults();
    }
  } catch (error) {
    showError(document.querySelector('#admin-login-error'), error.message);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const button = document.querySelector('#admin-login-submit');
  button.disabled = true;
  showError(document.querySelector('#admin-login-error'));
  try {
    const password = document.querySelector('#admin-password').value;
    const result = await api('/api/admin/login', { method: 'POST', body: JSON.stringify({ password }) });
    setCsrfToken(result.csrfToken);
    document.querySelector('#admin-login-form').reset();
    document.querySelector('#admin-login').hidden = true;
    document.querySelector('#admin-dashboard').hidden = false;
    await loadVaults();
  } catch (error) {
    showError(document.querySelector('#admin-login-error'), error.message || 'Admin sign in failed.');
  } finally {
    button.disabled = false;
  }
}

async function handleLogout() {
  try {
    await api('/api/admin/logout', { method: 'POST' });
    setCsrfToken('');
    state.vaults = [];
    state.selectedVault = null;
    document.querySelector('#admin-dashboard').hidden = true;
    document.querySelector('#admin-login').hidden = false;
  } catch (error) {
    showError(document.querySelector('#admin-error'), error.message);
  }
}

export function initAdminFeature({ goHome }) {
  document.querySelector('#admin-home').addEventListener('click', () => goHome());
  document.querySelector('#admin-login-form').addEventListener('submit', handleLogin);
  document.querySelector('#admin-unlock-form').addEventListener('submit', handleUnlock);
  document.querySelector('#admin-logout').addEventListener('click', handleLogout);
  document.querySelector('#admin-refresh').addEventListener('click', loadVaults);
}
