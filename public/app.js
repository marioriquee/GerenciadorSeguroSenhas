'use strict';

const state = {
  me: null,
  entries: [],
  users: [],
  audit: [],
  editingEntryId: null,
  visiblePasswords: new Set(),
  currentTab: 'vault'
};

const selectors = {
  setupScreen: document.querySelector('#setup-screen'),
  loginScreen: document.querySelector('#login-screen'),
  appScreen: document.querySelector('#app-screen'),
  setupForm: document.querySelector('#setup-form'),
  loginForm: document.querySelector('#login-form'),
  logoutButton: document.querySelector('#logout-button'),
  userChip: document.querySelector('#user-chip'),
  usersTab: document.querySelector('#users-tab'),
  auditTab: document.querySelector('#audit-tab'),
  searchInput: document.querySelector('#search-input'),
  entriesGrid: document.querySelector('#entries-grid'),
  entryCount: document.querySelector('#entry-count'),
  categoryCount: document.querySelector('#category-count'),
  newEntryButton: document.querySelector('#new-entry-button'),
  entryDialog: document.querySelector('#entry-dialog'),
  entryDialogTitle: document.querySelector('#entry-dialog-title'),
  entryForm: document.querySelector('#entry-form'),
  closeEntryDialog: document.querySelector('#close-entry-dialog'),
  cancelEntry: document.querySelector('#cancel-entry'),
  toggleEntryPassword: document.querySelector('#toggle-entry-password'),
  generatePassword: document.querySelector('#generate-password'),
  entryTitle: document.querySelector('#entry-title'),
  entryLogin: document.querySelector('#entry-login'),
  entryPassword: document.querySelector('#entry-password'),
  entryUrl: document.querySelector('#entry-url'),
  entryCategory: document.querySelector('#entry-category'),
  entryNotes: document.querySelector('#entry-notes'),
  userForm: document.querySelector('#user-form'),
  userFormTitle: document.querySelector('#user-form-title'),
  userEditingId: document.querySelector('#user-editing-id'),
  cancelUserEdit: document.querySelector('#cancel-user-edit'),
  usersBody: document.querySelector('#users-body'),
  auditBody: document.querySelector('#audit-body'),
  toast: document.querySelector('#toast')
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (response.status === 204) {
    return null;
  }

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || 'Operacao nao concluida.');
  }

  return payload;
}

function showToast(message) {
  selectors.toast.textContent = message;
  selectors.toast.classList.add('show');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    selectors.toast.classList.remove('show');
  }, 3200);
}

function setScreen(name) {
  selectors.setupScreen.classList.toggle('hidden', name !== 'setup');
  selectors.loginScreen.classList.toggle('hidden', name !== 'login');
  selectors.appScreen.classList.toggle('hidden', name !== 'app');
}

function formToObject(form) {
  const username = form.elements.username;
  if (username) {
    username.value = username.value.trim().toLowerCase();
  }
  return Object.fromEntries(new FormData(form).entries());
}

function setSubmitting(form, submitting) {
  for (const control of form.querySelectorAll('button, input, select, textarea')) {
    control.disabled = submitting;
  }
}

async function bootstrap() {
  try {
    const setup = await fetchJson('/api/setup');
    if (!setup.hasUsers) {
      setScreen(setup.setupEnabled ? 'setup' : 'login');
      return;
    }

    const me = await fetchJson('/api/me').catch(() => null);
    if (!me) {
      setScreen('login');
      return;
    }

    await enterApp(me.user);
  } catch (error) {
    showToast(error.message);
    setScreen('login');
  }
}

async function enterApp(user) {
  state.me = user;
  selectors.userChip.textContent = `${user.name} (${user.role === 'admin' ? 'admin' : 'usuario'})`;
  selectors.usersTab.classList.toggle('hidden', user.role !== 'admin');
  selectors.auditTab.classList.toggle('hidden', user.role !== 'admin');
  setScreen('app');
  await loadVault();
  switchTab('vault');
}

async function loadVault() {
  const payload = await fetchJson('/api/vault');
  state.entries = payload.entries;
  renderEntries();
}

async function loadUsers() {
  if (state.me?.role !== 'admin') {
    return;
  }
  const payload = await fetchJson('/api/users');
  state.users = payload.users;
  renderUsers();
}

async function loadAudit() {
  if (state.me?.role !== 'admin') {
    return;
  }
  const payload = await fetchJson('/api/audit');
  state.audit = payload.audit;
  renderAudit();
}

function switchTab(tabName) {
  state.currentTab = tabName;
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === tabName);
  });
  document.querySelector('#vault-view').classList.toggle('hidden', tabName !== 'vault');
  document.querySelector('#users-view').classList.toggle('hidden', tabName !== 'users');
  document.querySelector('#audit-view').classList.toggle('hidden', tabName !== 'audit');

  if (tabName === 'users') {
    loadUsers().catch((error) => showToast(error.message));
  }
  if (tabName === 'audit') {
    loadAudit().catch((error) => showToast(error.message));
  }
}

function filteredEntries() {
  const query = selectors.searchInput.value.trim().toLowerCase();
  if (!query) {
    return state.entries;
  }

  return state.entries.filter((entry) => [
    entry.title,
    entry.login,
    entry.url,
    entry.notes,
    entry.category
  ].some((value) => String(value || '').toLowerCase().includes(query)));
}

function renderEntries() {
  const entries = filteredEntries();
  selectors.entriesGrid.replaceChildren();
  selectors.entryCount.textContent = String(state.entries.length);
  selectors.categoryCount.textContent = String(new Set(state.entries.map((entry) => entry.category).filter(Boolean)).size);

  if (entries.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = state.entries.length === 0 ? 'Nenhuma senha cadastrada.' : 'Nenhum resultado encontrado.';
    selectors.entriesGrid.append(empty);
    return;
  }

  for (const entry of entries) {
    selectors.entriesGrid.append(createEntryCard(entry));
  }
}

function createEntryCard(entry) {
  const card = document.createElement('article');
  card.className = 'entry-card';

  const header = document.createElement('div');
  header.className = 'entry-title-row';

  const title = document.createElement('div');
  title.className = 'entry-title';
  title.textContent = entry.title;
  header.append(title);

  if (entry.category) {
    const pill = document.createElement('span');
    pill.className = 'pill';
    pill.textContent = entry.category;
    header.append(pill);
  }

  const details = document.createElement('div');
  details.className = 'entry-details';
  appendDetail(details, 'Login', entry.login || '-');
  appendDetail(details, 'Senha', state.visiblePasswords.has(entry.id) ? entry.password : '••••••••••••', 'password-value');
  appendDetail(details, 'URL', entry.url || '-');
  if (entry.notes) {
    appendDetail(details, 'Notas', entry.notes);
  }

  const actions = document.createElement('div');
  actions.className = 'entry-actions';
  actions.append(
    actionButton(state.visiblePasswords.has(entry.id) ? 'Ocultar' : 'Ver', () => {
      if (state.visiblePasswords.has(entry.id)) {
        state.visiblePasswords.delete(entry.id);
      } else {
        state.visiblePasswords.add(entry.id);
      }
      renderEntries();
    }),
    actionButton('Copiar', () => copyPassword(entry.password)),
    actionButton('Editar', () => openEntryDialog(entry)),
    actionButton('Excluir', () => deleteEntry(entry), 'danger-button')
  );

  card.append(header, details, actions);
  return card;
}

function appendDetail(parent, label, value, valueClass = '') {
  const item = document.createElement('div');
  const labelEl = document.createElement('span');
  labelEl.className = 'detail-label';
  labelEl.textContent = label;

  const valueEl = document.createElement('span');
  valueEl.className = `detail-value ${valueClass}`.trim();
  valueEl.textContent = value;

  item.append(labelEl, valueEl);
  parent.append(item);
}

function actionButton(label, onClick, className = 'secondary-button') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', onClick);
  return button;
}

async function copyPassword(password) {
  try {
    await navigator.clipboard.writeText(password);
    showToast('Senha copiada.');
  } catch {
    showToast('Nao foi possivel copiar automaticamente.');
  }
}

function openEntryDialog(entry = null) {
  state.editingEntryId = entry?.id || null;
  selectors.entryDialogTitle.textContent = entry ? 'Editar senha' : 'Nova senha';
  selectors.entryTitle.value = entry?.title || '';
  selectors.entryLogin.value = entry?.login || '';
  selectors.entryPassword.value = entry?.password || '';
  selectors.entryPassword.type = 'password';
  selectors.toggleEntryPassword.textContent = 'Ver';
  selectors.entryUrl.value = entry?.url || '';
  selectors.entryCategory.value = entry?.category || '';
  selectors.entryNotes.value = entry?.notes || '';
  selectors.entryDialog.showModal();
}

function closeEntryDialog() {
  selectors.entryDialog.close();
  selectors.entryForm.reset();
  state.editingEntryId = null;
}

function generatePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*_-+=';
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  selectors.entryPassword.value = Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join('');
}

async function saveEntry(event) {
  event.preventDefault();
  const body = formToObject(selectors.entryForm);
  setSubmitting(selectors.entryForm, true);

  try {
    if (state.editingEntryId) {
      await fetchJson(`/api/vault/${state.editingEntryId}`, { method: 'PUT', body });
      showToast('Senha atualizada.');
    } else {
      await fetchJson('/api/vault', { method: 'POST', body });
      showToast('Senha cadastrada.');
    }
    closeEntryDialog();
    await loadVault();
  } catch (error) {
    showToast(error.message);
  } finally {
    setSubmitting(selectors.entryForm, false);
  }
}

async function deleteEntry(entry) {
  const confirmed = window.confirm(`Excluir a senha "${entry.title}"?`);
  if (!confirmed) {
    return;
  }

  try {
    await fetchJson(`/api/vault/${entry.id}`, { method: 'DELETE' });
    state.visiblePasswords.delete(entry.id);
    showToast('Senha excluida.');
    await loadVault();
  } catch (error) {
    showToast(error.message);
  }
}

function renderUsers() {
  selectors.usersBody.replaceChildren();

  for (const user of state.users) {
    const row = document.createElement('tr');
    row.append(
      tableCell(user.name),
      tableCell(user.username),
      tableCell(user.role === 'admin' ? 'Administrador' : 'Usuario'),
      tableCell(user.active ? 'Ativo' : 'Desativado')
    );

    const actionCell = document.createElement('td');
    const actions = document.createElement('div');
    actions.className = 'entry-actions';
    actions.append(actionButton('Editar', () => editUser(user)));

    if (user.id !== state.me.id) {
      actions.append(actionButton('Excluir', () => deleteUser(user), 'danger-button'));
    }

    actionCell.append(actions);
    row.append(actionCell);
    selectors.usersBody.append(row);
  }
}

function resetUserForm() {
  selectors.userForm.reset();
  selectors.userEditingId.value = '';
  selectors.userFormTitle.textContent = 'Novo usuario';
  selectors.userForm.querySelector('button[type="submit"]').textContent = 'Criar usuario';
  selectors.cancelUserEdit.classList.add('hidden');
  selectors.userForm.elements.password.required = true;
}

function editUser(user) {
  selectors.userEditingId.value = user.id;
  selectors.userFormTitle.textContent = 'Editar usuario';
  selectors.userForm.elements.name.value = user.name || '';
  selectors.userForm.elements.username.value = user.username || '';
  selectors.userForm.elements.password.value = '';
  selectors.userForm.elements.role.value = user.role || 'user';
  selectors.userForm.elements.password.required = false;
  selectors.userForm.querySelector('button[type="submit"]').textContent = 'Salvar alteracoes';
  selectors.cancelUserEdit.classList.remove('hidden');
  selectors.userForm.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function deleteUser(user) {
  const confirmed = window.confirm(
    `Excluir DEFINITIVAMENTE o usuario "${user.username}"?\n\n` +
    'O registro sera removido do servidor e todas as sessoes desse usuario serao invalidadas. Essa acao nao pode ser desfeita.'
  );

  if (!confirmed) {
    return;
  }

  try {
    await fetchJson(`/api/users/${user.id}`, { method: 'DELETE' });
    showToast('Usuario excluido definitivamente.');
    resetUserForm();
    await loadUsers();
  } catch (error) {
    showToast(error.message);
  }
}

function renderAudit() {
  selectors.auditBody.replaceChildren();

  for (const item of state.audit) {
    const row = document.createElement('tr');
    row.append(
      tableCell(new Date(item.at).toLocaleString('pt-BR')),
      tableCell(item.username),
      tableCell(item.action),
      tableCell(item.summary)
    );
    selectors.auditBody.append(row);
  }
}

function tableCell(value) {
  const cell = document.createElement('td');
  cell.textContent = value || '';
  return cell;
}

async function disableUser(user) {
  const confirmed = window.confirm(`Desativar o usuario "${user.username}"?`);
  if (!confirmed) {
    return;
  }

  try {
    await fetchJson(`/api/users/${user.id}`, { method: 'DELETE' });
    showToast('Usuario desativado.');
    await loadUsers();
  } catch (error) {
    showToast(error.message);
  }
}

selectors.setupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = formToObject(selectors.setupForm);
  setSubmitting(selectors.setupForm, true);

  try {
    const payload = await fetchJson('/api/setup/first-admin', {
      method: 'POST',
      body
    });
    selectors.setupForm.reset();
    await enterApp(payload.user);
  } catch (error) {
    showToast(error.message);
  } finally {
    setSubmitting(selectors.setupForm, false);
  }
});

selectors.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = formToObject(selectors.loginForm);
  setSubmitting(selectors.loginForm, true);

  try {
    const payload = await fetchJson('/api/login', {
      method: 'POST',
      body
    });
    selectors.loginForm.reset();
    await enterApp(payload.user);
  } catch (error) {
    showToast(error.message);
  } finally {
    setSubmitting(selectors.loginForm, false);
  }
});

selectors.logoutButton.addEventListener('click', async () => {
  try {
    await fetchJson('/api/logout', { method: 'POST' });
  } catch {
  }
  state.me = null;
  state.entries = [];
  state.users = [];
  state.visiblePasswords.clear();
  setScreen('login');
});

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

selectors.searchInput.addEventListener('input', renderEntries);
selectors.newEntryButton.addEventListener('click', () => openEntryDialog());
selectors.closeEntryDialog.addEventListener('click', closeEntryDialog);
selectors.cancelEntry.addEventListener('click', closeEntryDialog);
selectors.entryForm.addEventListener('submit', saveEntry);
selectors.generatePassword.addEventListener('click', generatePassword);
selectors.toggleEntryPassword.addEventListener('click', () => {
  const visible = selectors.entryPassword.type === 'text';
  selectors.entryPassword.type = visible ? 'password' : 'text';
  selectors.toggleEntryPassword.textContent = visible ? 'Ver' : 'Ocultar';
});

selectors.userForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = formToObject(selectors.userForm);
  const editingId = selectors.userEditingId.value;
  setSubmitting(selectors.userForm, true);

  try {
    if (editingId) {
      if (!body.password) {
        delete body.password;
      }
      await fetchJson(`/api/users/${editingId}`, { method: 'PUT', body });
      showToast('Usuario atualizado.');
    } else {
      await fetchJson('/api/users', { method: 'POST', body });
      showToast('Usuario criado.');
    }

    resetUserForm();
    await loadUsers();
  } catch (error) {
    showToast(error.message);
  } finally {
    setSubmitting(selectors.userForm, false);
  }
});

selectors.cancelUserEdit.addEventListener('click', resetUserForm);

bootstrap();
