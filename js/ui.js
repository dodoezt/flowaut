const views = {
  home: document.querySelector('#home-view'),
  form: document.querySelector('#form-view'),
  unlock: document.querySelector('#unlock-view'),
  room: document.querySelector('#room-view'),
  admin: document.querySelector('#admin-view'),
};

export function showView(name) {
  for (const [key, element] of Object.entries(views)) element.hidden = key !== name;
}

export function showError(element, message = '') {
  element.textContent = message;
  element.hidden = !message;
}
