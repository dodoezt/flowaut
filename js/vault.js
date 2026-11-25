import { api, apiUrl, setCsrfToken, getCsrfToken } from './api.js';
import { deriveKey, encryptText, decryptText, encryptBytes, decryptBytes, toBase64Url, encoder } from './crypto.js';
import { showView, showError } from './ui.js';

const state = { formMode: 'create', vault: null, key: null, editingId: null };
const APP_BASE = new URL('.', document.baseURI).pathname.replace(/\/$/, '');

export function clearVaultState() {
  state.vault = null;
  state.key = null;
  state.editingId = null;
  setCsrfToken('');
  closeEditor();
}

export function showUnlockView() {
  clearVaultState();
  document.querySelector('#unlock-form').reset();
  showError(document.querySelector('#unlock-error'));
  showView('unlock');
  document.querySelector('#unlock-password').focus();
}

export function openForm(mode) {
  state.formMode = mode;
  const create = mode === 'create';
  document.querySelector('#form-title').textContent = create ? 'Create vault' : 'Enter vault';
  document.querySelector('#form-description').textContent = create
    ? 'Choose a vault name and password. The password encrypts your notes.'
    : 'Use the vault name and password shared with you.';
  document.querySelector('#form-submit').textContent = create ? 'Create vault' : 'Enter vault';
  document.querySelector('#room-form').reset();
  showError(document.querySelector('#form-error'));
  showView('form');
  document.querySelector('#room-name').focus();
}

function setVault(vault, key, csrfToken) {
  state.vault = vault;
  state.key = key;
  state.editingId = null;
  setCsrfToken(csrfToken);
  document.querySelector('#room-title').textContent = vault.name;
  showView('room');
  loadContents();
  loadFiles();
}

async function loadFiles() {
  const target = document.querySelector('#files');
  target.replaceChildren();
  try {
    const { files } = await api(`/api/vaults/${state.vault.id}/files`);
    for (const file of files) {
      const name = await decryptText({ ciphertext: file.encrypted_name, iv: file.name_iv }, state.key);
      const row = document.createElement('article');
      row.className = 'content-card file-row';
      const label = document.createElement('span');
      label.textContent = `${name} · ${(Number(file.byte_size) / 1048576).toFixed(2)} MB`;
      const actions = document.createElement('div');
      actions.className = 'content-actions';
      const download = makeAction('Download', async () => {
        const response = await fetch(apiUrl(`/api/vaults/${state.vault.id}/files/${file.id}`), { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Could not download file');
        const clear = await decryptBytes(await response.arrayBuffer(), file.file_iv, state.key);
        const url = URL.createObjectURL(new Blob([clear]));
        const link = document.createElement('a');
        link.href = url;
        link.download = name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      });
      const remove = makeAction('Delete', async () => {
        if (!confirm('Delete this file?')) return;
        await api(`/api/vaults/${state.vault.id}/files/${file.id}`, { method: 'DELETE' });
        await loadFiles();
      }, true);
      actions.append(download, remove);
      row.append(label, actions);
      target.append(row);
    }
  } catch (error) {
    showError(document.querySelector('#file-error'), error.message);
  }
}

async function uploadFiles(event) {
  const input = event.currentTarget;
  const picker = document.querySelector('.file-pick');
  const status = document.querySelector('#upload-status');
  const message = document.querySelector('#upload-message');
  const progress = document.querySelector('#upload-progress');
  showError(document.querySelector('#file-error'));
  const files = Array.from(input.files);
  if (!files.length) {
    status.hidden = true;
    message.textContent = '';
    input.value = '';
    return;
  }

  input.disabled = true;
  picker.setAttribute('aria-disabled', 'true');
  status.hidden = false;
  let completed = 0;
  try {
    for (const [index, file] of files.entries()) {
      if (file.size + 16 > 25 * 1024 * 1024) {
        showError(document.querySelector('#file-error'), `${file.name} exceeds the 25 MB limit.`);
        completed++;
        continue;
      }
      try {
        message.textContent = `Encrypting ${file.name} (${index + 1}/${files.length})…`;
        progress.removeAttribute('value');
        const encryptedFile = await encryptBytes(await file.arrayBuffer(), state.key);
        const encryptedName = await encryptBytes(encoder.encode(file.name), state.key);
        const headers = {
          'Content-Type': 'application/octet-stream',
          'X-CSRF-Token': getCsrfToken(),
          'X-File-Name': toBase64Url(new Uint8Array(encryptedName.ciphertext)),
          'X-Name-Iv': toBase64Url(encryptedName.iv),
          'X-File-Iv': toBase64Url(encryptedFile.iv),
        };
        message.textContent = `Uploading ${file.name} (${index + 1}/${files.length})…`;
        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', apiUrl(`/api/vaults/${state.vault.id}/files`));
          xhr.withCredentials = true;
          for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value);
          xhr.upload.onprogress = (progressEvent) => {
            if (progressEvent.lengthComputable) {
              progress.value = Math.round((completed + progressEvent.loaded / progressEvent.total) / files.length * 100);
            }
          };
          xhr.onload = () => xhr.status >= 200 && xhr.status < 300
            ? resolve()
            : reject(new Error(JSON.parse(xhr.responseText || '{}').error || 'Upload failed'));
          xhr.onerror = () => reject(new Error('Network error during upload'));
          xhr.send(encryptedFile.ciphertext);
        });
        completed++;
        progress.value = Math.round(completed / files.length * 100);
      } catch (error) {
        showError(document.querySelector('#file-error'), error.message);
        completed++;
      }
    }
  } finally {
    input.disabled = false;
    picker.removeAttribute('aria-disabled');
    message.textContent = completed ? 'Upload process finished.' : 'Upload failed.';
    progress.value = 100;
    setTimeout(() => { status.hidden = true; message.textContent = ''; }, 1800);
  }
  input.value = '';
  loadFiles();
}

async function loadContents() {
  const target = document.querySelector('#contents');
  target.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'muted';
  loading.textContent = 'Loading encrypted notes…';
  target.append(loading);
  try {
    const result = await api(`/api/vaults/${state.vault.id}/contents`);
    target.replaceChildren();
    if (!result.contents.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No notes yet. Create one to share text in this vault.';
      target.append(empty);
      return;
    }
    for (const record of result.contents) {
      const text = await decryptText(record, state.key);
      target.append(makeContentCard(record, text));
    }
    showError(document.querySelector('#room-error'));
  } catch (error) {
    target.replaceChildren();
    showError(document.querySelector('#room-error'), error.message || 'Could not load vault contents.');
  }
}

function makeContentCard(record, text) {
  const card = document.createElement('article');
  card.className = 'content-card';
  const body = document.createElement('pre');
  body.className = 'content-text';
  body.textContent = text;
  card.append(body);
  const meta = document.createElement('div');
  meta.className = 'content-meta';
  meta.textContent = `Saved ${new Date(record.updated_at || record.created_at).toLocaleString()}`;
  card.append(meta);
  const actions = document.createElement('div');
  actions.className = 'content-actions';
  const copy = makeAction('Copy', async () => {
    await navigator.clipboard.writeText(text);
    copy.textContent = 'Copied';
    setTimeout(() => { copy.textContent = 'Copy'; }, 1200);
  });
  const edit = makeAction('Edit', () => openEditor(record.id, text));
  const remove = makeAction('Delete', async () => {
    if (!window.confirm('Delete this note?')) return;
    await api(`/api/vaults/${state.vault.id}/contents/${record.id}`, { method: 'DELETE' });
    await loadContents();
  }, true);
  actions.append(copy, edit, remove);
  card.append(actions);
  return card;
}

function makeAction(label, action, danger = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `small-button${danger ? ' danger' : ''}`;
  button.textContent = label;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await action();
    } catch (error) {
      showError(document.querySelector('#room-error'), error.message || 'The action failed.');
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

function openEditor(id = null, text = '') {
  state.editingId = id;
  document.querySelector('#markdown-input').value = text;
  document.querySelector('#save-content').textContent = id ? 'Save changes' : 'Save encrypted note';
  document.querySelector('#editor').hidden = false;
  document.querySelector('#markdown-input').focus();
}

function closeEditor() {
  state.editingId = null;
  document.querySelector('#markdown-input').value = '';
  document.querySelector('#editor').hidden = true;
}

async function saveContent() {
  const text = document.querySelector('#markdown-input').value;
  if (!text.trim()) {
    showError(document.querySelector('#room-error'), 'Write some text before saving.');
    return;
  }
  const button = document.querySelector('#save-content');
  button.disabled = true;
  showError(document.querySelector('#room-error'));
  try {
    const encrypted = await encryptText(text, state.key);
    const editingId = state.editingId;
    await api(
      editingId
        ? `/api/vaults/${state.vault.id}/contents/${editingId}`
        : `/api/vaults/${state.vault.id}/contents`,
      { method: editingId ? 'PUT' : 'POST', body: JSON.stringify(encrypted) },
    );
    closeEditor();
    await loadContents();
  } catch (error) {
    showError(document.querySelector('#room-error'), error.message || 'Could not save this note.');
  } finally {
    button.disabled = false;
  }
}

async function handleVaultForm(event) {
  event.preventDefault();
  const submit = document.querySelector('#form-submit');
  const errorElement = document.querySelector('#form-error');
  const data = new FormData(event.currentTarget);
  const name = String(data.get('name') || '').trim();
  const password = String(data.get('password') || '');
  submit.disabled = true;
  showError(errorElement);
  try {
    const result = state.formMode === 'create'
      ? await api('/api/vaults', { method: 'POST', body: JSON.stringify({ name, password }) })
      : await api('/api/vaults/enter', { method: 'POST', body: JSON.stringify({ name, password }) });
    const key = await deriveKey(password, result.room.salt);
    history.pushState({}, '', `${APP_BASE}/vault/${result.room.id}`);
    setVault(result.room, key, result.csrfToken);
  } catch (error) {
    showError(errorElement, error.message || 'Could not open this vault.');
  } finally {
    submit.disabled = false;
  }
}

async function handleUnlock(event) {
  event.preventDefault();
  const submit = document.querySelector('#unlock-submit');
  const errorElement = document.querySelector('#unlock-error');
  const password = document.querySelector('#unlock-password').value;
  const match = location.pathname.slice(APP_BASE.length).match(/^\/vault\/([0-9a-f-]{36})\/?$/i);
  if (!match) return;
  submit.disabled = true;
  showError(errorElement);
  try {
    const result = await api(`/api/vaults/${match[1]}/unlock`, { method: 'POST', body: JSON.stringify({ password }) });
    const key = await deriveKey(password, result.room.salt);
    setVault(result.room, key, result.csrfToken);
  } catch (error) {
    showError(errorElement, error.message || 'Could not unlock this vault.');
  } finally {
    submit.disabled = false;
  }
}

export function initVaultFeature({ goHome }) {
  document.querySelector('#show-create').addEventListener('click', () => openForm('create'));
  document.querySelector('#show-enter').addEventListener('click', () => openForm('enter'));
  document.querySelector('#room-form').addEventListener('submit', handleVaultForm);
  document.querySelector('#unlock-form').addEventListener('submit', handleUnlock);
  document.querySelector('#new-content').addEventListener('click', () => openEditor());
  document.querySelector('#cancel-edit').addEventListener('click', closeEditor);
  document.querySelector('#save-content').addEventListener('click', saveContent);
  document.querySelector('#leave-room').addEventListener('click', () => goHome());
  document.querySelector('#file-input').addEventListener('change', uploadFiles);
}
