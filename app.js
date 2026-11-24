const views = {
  home: document.querySelector('#home-view'),
  form: document.querySelector('#form-view'),
  unlock: document.querySelector('#unlock-view'),
  room: document.querySelector('#room-view'),
};

const state = { formMode: 'create', room: null, key: null, csrfToken: '', editingId: null };
const APP_BASE = new URL('.', document.baseURI).pathname.replace(/\/$/, '');
const apiUrl = (path) => `${APP_BASE}${path}`;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PBKDF2_ITERATIONS = 310_000;

function showView(name) {
  for (const [key, element] of Object.entries(views)) element.hidden = key !== name;
}

function showError(element, message = '') {
  element.textContent = message;
  element.hidden = !message;
}

async function api(url, options = {}) {
  url = apiUrl(url);
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && !['GET', 'HEAD'].includes(options.method)) headers.set('X-CSRF-Token', state.csrfToken);
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
  return result;
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return fromBase64(normalized + '='.repeat((4 - normalized.length % 4) % 4));
}

async function deriveKey(password, saltBase64) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromBase64(saltBase64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptText(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, encoder.encode(text));
  return { ciphertext: toBase64Url(new Uint8Array(encrypted)), iv: toBase64Url(iv) };
}

async function decryptText(record) {
  const cleartext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64Url(record.iv) },
    state.key,
    fromBase64Url(record.ciphertext),
  );
  return decoder.decode(cleartext);
}

function setRoom(room, key, csrfToken) {
  state.room = room;
  state.key = key;
  state.csrfToken = csrfToken;
  state.editingId = null;
  document.querySelector('#room-title').textContent = room.name;
  showView('room');
  loadContents();
  loadFiles();
}

async function loadFiles() {
  const target = document.querySelector('#files');
  target.replaceChildren();
  try {
    const { files } = await api(`/api/vaults/${state.room.id}/files`);
    for (const file of files) {
      const name = await decryptText({ ciphertext: file.encrypted_name, iv: file.name_iv });
      const row = document.createElement('article');
      row.className = 'content-card file-row';
      const label = document.createElement('span');
      label.textContent = `${name} · ${(Number(file.byte_size) / 1048576).toFixed(2)} MB`;
      const actions = document.createElement('div'); actions.className = 'content-actions';
      const download = makeAction('Download', async () => {
        const response = await fetch(apiUrl(`/api/vaults/${state.room.id}/files/${file.id}`), { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Could not download file');
        const cipher = await response.arrayBuffer();
        const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(file.file_iv) }, state.key, cipher);
        const url = URL.createObjectURL(new Blob([clear]));
        const link = document.createElement('a'); link.href = url; link.download = name; link.click();
        URL.revokeObjectURL(url);
      });
      const remove = makeAction('Delete', async () => {
        if (!confirm('Delete this file?')) return;
        await api(`/api/vaults/${state.room.id}/files/${file.id}`, { method: 'DELETE' }); loadFiles();
      }, true);
      actions.append(download, remove); row.append(label, actions); target.append(row);
    }
  } catch (error) { showError(document.querySelector('#file-error'), error.message); }
}

async function uploadFiles(event) {
  const input = event.currentTarget;
  const picker = document.querySelector('.file-pick');
  const status = document.querySelector('#upload-status');
  const message = document.querySelector('#upload-message');
  const progress = document.querySelector('#upload-progress');
  showError(document.querySelector('#file-error'));
  const files = Array.from(input.files);
  input.disabled = true; picker.setAttribute('aria-disabled', 'true'); status.hidden = false;
  let completed = 0;
  try {
    for (const [index, file] of files.entries()) {
      if (file.size + 16 > 25 * 1024 * 1024) { showError(document.querySelector('#file-error'), `${file.name} exceeds the 25 MB limit.`); completed++; continue; }
      try {
        message.textContent = `Encrypting ${file.name} (${index + 1}/${files.length})…`;
        progress.removeAttribute('value');
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, await file.arrayBuffer());
      const nameIv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedName = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nameIv }, state.key, encoder.encode(file.name));
      const headers = { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': state.csrfToken, 'X-File-Name': toBase64Url(new Uint8Array(encryptedName)), 'X-Name-Iv': toBase64Url(nameIv), 'X-File-Iv': toBase64Url(iv) };
        message.textContent = `Uploading ${file.name} (${index + 1}/${files.length})…`;
        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest(); xhr.open('POST', apiUrl(`/api/vaults/${state.room.id}/files`)); xhr.withCredentials = true;
          for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value);
          xhr.upload.onprogress = (progressEvent) => {
            if (progressEvent.lengthComputable) progress.value = Math.round((completed + progressEvent.loaded / progressEvent.total) / files.length * 100);
          };
          xhr.onload = () => xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(JSON.parse(xhr.responseText || '{}').error || 'Upload failed'));
          xhr.onerror = () => reject(new Error('Network error during upload'));
          xhr.send(encrypted);
        });
        completed++; progress.value = Math.round(completed / files.length * 100);
      } catch (error) { showError(document.querySelector('#file-error'), error.message); completed++; }
    }
  } finally {
    input.disabled = false; picker.removeAttribute('aria-disabled');
    message.textContent = completed ? 'Upload process finished.' : 'No files selected.';
    progress.value = 100;
    setTimeout(() => { status.hidden = true; }, 1800);
  }
  input.value = ''; loadFiles();
}

async function loadContents() {
  const target = document.querySelector('#contents');
  target.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'muted';
  loading.textContent = 'Loading encrypted notes…';
  target.append(loading);
  try {
    const result = await api(`/api/vaults/${state.room.id}/contents`);
    target.replaceChildren();
    if (result.contents.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No notes yet. Create one to send text to this room.';
      target.append(empty);
      return;
    }
    for (const record of result.contents) {
      const text = await decryptText(record);
      target.append(makeContentCard(record, text));
    }
    showError(document.querySelector('#room-error'));
  } catch (error) {
    target.replaceChildren();
    showError(document.querySelector('#room-error'), error.message || 'Could not load room contents.');
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
    await api(`/api/vaults/${state.room.id}/contents/${record.id}`, { method: 'DELETE' });
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
    const encrypted = await encryptText(text);
    const editingId = state.editingId;
    await api(
      editingId
        ? `/api/vaults/${state.room.id}/contents/${editingId}`
        : `/api/vaults/${state.room.id}/contents`,
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

function openForm(mode) {
  state.formMode = mode;
  const create = mode === 'create';
  document.querySelector('#form-title').textContent = create ? 'Create room' : 'Enter room';
  document.querySelector('#form-description').textContent = create
    ? 'Choose a room name and password. The password encrypts your notes.'
    : 'Use the room name and password shared with you.';
  document.querySelector('#form-submit').textContent = create ? 'Create room' : 'Enter room';
  document.querySelector('#room-form').reset();
  showError(document.querySelector('#form-error'));
  showView('form');
  document.querySelector('#room-name').focus();
}

function goHome(replace = false) {
  const method = replace ? 'replaceState' : 'pushState';
  history[method]({}, '', `${APP_BASE}/`);
  state.room = null;
  state.key = null;
  state.csrfToken = '';
  closeEditor();
  showView('home');
}

async function handleRoomForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = document.querySelector('#form-submit');
  const errorElement = document.querySelector('#form-error');
  const data = new FormData(form);
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
    setRoom(result.room, key, result.csrfToken);
  } catch (error) {
    showError(errorElement, error.message || 'Could not open this room.');
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
  const roomId = match[1];
  submit.disabled = true;
  showError(errorElement);
  try {
    const result = await api(`/api/vaults/${roomId}/unlock`, { method: 'POST', body: JSON.stringify({ password }) });
    const key = await deriveKey(password, result.room.salt);
    setRoom(result.room, key, result.csrfToken);
  } catch (error) {
    showError(errorElement, error.message || 'Could not unlock this room.');
  } finally {
    submit.disabled = false;
  }
}

function route() {
  const routePath = location.pathname.slice(APP_BASE.length) || '/';
  const match = routePath.match(/^\/vault\/([0-9a-f-]{36})\/?$/i);
  if (!match) {
    showView('home');
    return;
  }
  state.room = null;
  state.key = null;
  state.csrfToken = '';
  document.querySelector('#unlock-form').reset();
  showError(document.querySelector('#unlock-error'));
  showView('unlock');
  document.querySelector('#unlock-password').focus();
}

document.querySelector('#show-create').addEventListener('click', () => openForm('create'));
document.querySelector('#show-enter').addEventListener('click', () => openForm('enter'));
document.querySelectorAll('[data-home]').forEach((element) => element.addEventListener('click', (event) => {
  event.preventDefault();
  goHome();
}));
document.querySelector('#room-form').addEventListener('submit', handleRoomForm);
document.querySelector('#unlock-form').addEventListener('submit', handleUnlock);
document.querySelector('#new-content').addEventListener('click', () => openEditor());
document.querySelector('#cancel-edit').addEventListener('click', closeEditor);
document.querySelector('#save-content').addEventListener('click', saveContent);
document.querySelector('#leave-room').addEventListener('click', () => goHome());
document.querySelector('#file-input').addEventListener('change', uploadFiles);
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
