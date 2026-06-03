'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);
const ROOT_DIR = path.resolve(__dirname, '..');
loadDotEnv(path.join(ROOT_DIR, '.env'));
const DEFAULT_PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const DEFAULT_DATA_DIR = path.join(ROOT_DIR, 'data');
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 8;
const JSON_LIMIT_BYTES = 1024 * 1024;
const SCRYPT_PARAMS = {
  N: 16384,
  r: 8,
  p: 1,
  keyLength: 64,
  maxmem: 64 * 1024 * 1024
};

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function loadDotEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const separator = trimmed.indexOf('=');
    if (separator === -1) {
      continue;
    }

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();

    if (!/^[A-Z_][A-Z0-9_]*$/i.test(key) || Object.hasOwn(process.env, key)) {
      continue;
    }

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  }
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  return ['1', 'true', 'yes', 'sim', 's'].includes(String(value).trim().toLowerCase());
}

function quoteSqlName(name) {
  const parts = String(name || '').split('.').map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0 || parts.length > 2) {
    throw new Error(`Nome SQL invalido: ${name}`);
  }

  return parts.map((part) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(part)) {
      throw new Error(`Nome SQL invalido: ${name}`);
    }
    return `[${part}]`;
  }).join('.');
}

function toIsoOrNull(value) {
  if (!value) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  return new Date(value).toISOString();
}

function toSqlDate(value) {
  return value ? new Date(value) : null;
}

function createPasswordManagerServer(options = {}) {
  const publicDir = path.resolve(options.publicDir || DEFAULT_PUBLIC_DIR);
  const dataDir = path.resolve(options.dataDir || process.env.DATA_DIR || DEFAULT_DATA_DIR);
  const databaseFile = path.join(dataDir, 'database.json');
  const masterKeyFile = path.join(dataDir, 'master.key');
  const storageProvider = String(options.storageProvider || process.env.DB_PROVIDER || 'file').trim().toLowerCase();
  const setupToken = String(options.setupToken ?? process.env.APP_SETUP_TOKEN ?? '').trim();
  const useSqlServer = storageProvider === 'sqlserver';
  const sqlTables = {
    users: quoteSqlName(process.env.SQLSERVER_TABLE_USUARIOS || 'dbo.fatoUsuarios'),
    entries: quoteSqlName(process.env.SQLSERVER_TABLE_SENHAS || 'dbo.fatoSenhasCofre'),
    audit: quoteSqlName(process.env.SQLSERVER_TABLE_AUDITORIA || 'dbo.fatoAuditoria')
  };
  const sessions = new Map();
  const loginFailures = new Map();

  let db = null;
  let masterKey = null;
  let sql = null;
  let sqlPool = null;
  let writeQueue = Promise.resolve();

  async function init() {
    if (storageProvider !== 'file' && storageProvider !== 'sqlserver') {
      throw new Error('DB_PROVIDER deve ser file ou sqlserver.');
    }

    await fsp.mkdir(dataDir, { recursive: true });
    masterKey = await loadMasterKey();
    if (useSqlServer) {
      await initSqlServer();
    }
    db = await loadDatabase();
  }

  async function initSqlServer() {
    if (sqlPool) {
      return;
    }

    try {
      sql = require('mssql');
    } catch {
      throw new Error('Dependencia mssql nao instalada. Rode: npm.cmd install');
    }

    const server = process.env.SQLSERVER_HOST || '192.168.176.19';
    const database = process.env.SQLSERVER_DATABASE;
    const user = process.env.SQLSERVER_USER;
    const password = process.env.SQLSERVER_PASSWORD;

    if (!database || !user || !password) {
      throw new Error('Preencha SQLSERVER_DATABASE, SQLSERVER_USER e SQLSERVER_PASSWORD no .env.');
    }

    const config = {
      server,
      database,
      user,
      password,
      pool: {
        max: Number(process.env.SQLSERVER_POOL_MAX || 10),
        min: 0,
        idleTimeoutMillis: 30000
      },
      options: {
        encrypt: parseBoolean(process.env.SQLSERVER_ENCRYPT, false),
        trustServerCertificate: parseBoolean(process.env.SQLSERVER_TRUST_SERVER_CERTIFICATE, true),
        enableArithAbort: true
      }
    };

    if (process.env.SQLSERVER_INSTANCE) {
      config.options.instanceName = process.env.SQLSERVER_INSTANCE;
    } else {
      config.port = Number(process.env.SQLSERVER_PORT || 1433);
    }

    sqlPool = await new sql.ConnectionPool(config).connect();
  }

  async function loadMasterKey() {
    if (process.env.APP_MASTER_KEY) {
      const envKey = process.env.APP_MASTER_KEY.trim();
      const parsed = /^[a-f0-9]{64}$/i.test(envKey)
        ? Buffer.from(envKey, 'hex')
        : Buffer.from(envKey, 'base64');

      if (parsed.length !== 32) {
        throw new Error('APP_MASTER_KEY precisa ter 32 bytes em hex ou base64.');
      }

      return parsed;
    }

    try {
      const stored = (await fsp.readFile(masterKeyFile, 'utf8')).trim();
      const parsed = /^[a-f0-9]{64}$/i.test(stored)
        ? Buffer.from(stored, 'hex')
        : Buffer.from(stored, 'base64');

      if (parsed.length !== 32) {
        throw new Error('master.key invalido: esperado 32 bytes.');
      }

      return parsed;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }

      const generated = crypto.randomBytes(32);
      await fsp.writeFile(masterKeyFile, `${generated.toString('hex')}\n`, { mode: 0o600 });
      return generated;
    }
  }

  async function loadDatabase() {
    if (useSqlServer) {
      return loadSqlDatabase();
    }

    try {
      const raw = await fsp.readFile(databaseFile, 'utf8');
      return normalizeDatabase(JSON.parse(raw));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }

      const initial = normalizeDatabase({});
      await saveDatabase(initial);
      return initial;
    }
  }

  function normalizeDatabase(current) {
    return {
      version: 1,
      users: Array.isArray(current.users) ? current.users : [],
      entries: Array.isArray(current.entries) ? current.entries : [],
      audit: Array.isArray(current.audit) ? current.audit : []
    };
  }

  async function saveDatabase(nextDb = db) {
    if (useSqlServer) {
      writeQueue = writeQueue.then(() => saveSqlDatabase(nextDb), () => saveSqlDatabase(nextDb));
      await writeQueue;
      return;
    }

    const write = async () => {
      const tmpFile = `${databaseFile}.${process.pid}.${Date.now()}.tmp`;
      await fsp.writeFile(tmpFile, JSON.stringify(nextDb, null, 2));
      await fsp.rename(tmpFile, databaseFile);
    };

    writeQueue = writeQueue.then(write, write);
    await writeQueue;
  }

  async function loadSqlDatabase() {
    const [usersResult, entriesResult, auditResult] = await Promise.all([
      sqlPool.request().query(`
        SELECT
          Id,
          Nome,
          Usuario,
          Perfil,
          Ativo,
          AlgoritmoHashSenha,
          SaltSenha,
          HashSenha,
          ParametrosHashSenha,
          CriadoEm,
          AtualizadoEm,
          UltimoLoginEm
        FROM ${sqlTables.users}
        ORDER BY CriadoEm ASC
      `),
      sqlPool.request().query(`
        SELECT
          Id,
          Titulo,
          Login,
          Url,
          Categoria,
          Observacoes,
          AlgoritmoCriptografia,
          SenhaCriptografada,
          VetorInicial,
          TagAutenticacao,
          CriadoPorUsuarioId,
          AtualizadoPorUsuarioId,
          CriadoEm,
          AtualizadoEm
        FROM ${sqlTables.entries}
        ORDER BY Titulo ASC
      `),
      sqlPool.request().query(`
        SELECT TOP (300)
          Id,
          UsuarioId,
          Usuario,
          Acao,
          RegistroAlvoId,
          Resumo,
          CriadoEm
        FROM ${sqlTables.audit}
        ORDER BY CriadoEm DESC
      `)
    ]);

    return normalizeDatabase({
      users: usersResult.recordset.map(mapSqlUser),
      entries: entriesResult.recordset.map(mapSqlEntry),
      audit: auditResult.recordset.map(mapSqlAudit)
    });
  }

  async function saveSqlDatabase(nextDb) {
    const transaction = new sql.Transaction(sqlPool);

    try {
      await transaction.begin();
      await new sql.Request(transaction).query(`
        DELETE FROM ${sqlTables.audit};
        DELETE FROM ${sqlTables.entries};
        DELETE FROM ${sqlTables.users};
      `);

      for (const user of nextDb.users) {
        await insertSqlUser(transaction, user);
      }
      for (const entry of nextDb.entries) {
        await insertSqlEntry(transaction, entry);
      }
      for (const auditItem of nextDb.audit.slice().reverse()) {
        await insertSqlAudit(transaction, auditItem);
      }

      await transaction.commit();
    } catch (error) {
      await transaction.rollback().catch(() => {});
      throw error;
    }
  }

  function mapSqlUser(row) {
    const params = row.ParametrosHashSenha ? JSON.parse(row.ParametrosHashSenha) : SCRYPT_PARAMS;
    return {
      id: String(row.Id).toLowerCase(),
      name: row.Nome,
      username: String(row.Usuario).toLowerCase(),
      role: fromSqlRole(row.Perfil),
      active: row.Ativo !== false,
      passwordHash: {
        algorithm: row.AlgoritmoHashSenha || 'scrypt',
        params,
        salt: Buffer.from(row.SaltSenha).toString('base64'),
        hash: Buffer.from(row.HashSenha).toString('base64')
      },
      createdAt: toIsoOrNull(row.CriadoEm),
      updatedAt: toIsoOrNull(row.AtualizadoEm),
      lastLoginAt: toIsoOrNull(row.UltimoLoginEm)
    };
  }

  function mapSqlEntry(row) {
    const id = String(row.Id).toLowerCase();
    return {
      id,
      title: row.Titulo,
      login: row.Login || '',
      url: row.Url || '',
      notes: row.Observacoes || '',
      category: row.Categoria || '',
      password: {
        algorithm: row.AlgoritmoCriptografia || 'aes-256-gcm',
        iv: Buffer.from(row.VetorInicial).toString('base64'),
        tag: Buffer.from(row.TagAutenticacao).toString('base64'),
        ciphertext: Buffer.from(row.SenhaCriptografada).toString('base64')
      },
      createdAt: toIsoOrNull(row.CriadoEm),
      updatedAt: toIsoOrNull(row.AtualizadoEm),
      createdBy: String(row.CriadoPorUsuarioId).toLowerCase(),
      updatedBy: String(row.AtualizadoPorUsuarioId).toLowerCase()
    };
  }

  function mapSqlAudit(row) {
    return {
      id: String(row.Id).toLowerCase(),
      at: toIsoOrNull(row.CriadoEm),
      userId: row.UsuarioId ? String(row.UsuarioId).toLowerCase() : null,
      username: row.Usuario || 'sistema',
      action: row.Acao,
      targetId: row.RegistroAlvoId ? String(row.RegistroAlvoId).toLowerCase() : null,
      summary: row.Resumo || ''
    };
  }

  function toSqlRole(role) {
    const adminValue = process.env.SQLSERVER_ROLE_ADMIN || 'administrador';
    const userValue = process.env.SQLSERVER_ROLE_USER || 'usuario';
    return role === 'admin' ? adminValue : userValue;
  }

  function fromSqlRole(role) {
    const value = String(role || '').toLowerCase();
    const adminValue = String(process.env.SQLSERVER_ROLE_ADMIN || 'administrador').toLowerCase();
    return value === adminValue || value === 'admin' ? 'admin' : 'user';
  }

  async function insertSqlUser(transaction, user) {
    await new sql.Request(transaction)
      .input('Id', sql.UniqueIdentifier, user.id)
      .input('Nome', sql.NVarChar(100), user.name)
      .input('Usuario', sql.NVarChar(40), user.username)
      .input('Perfil', sql.NVarChar(20), toSqlRole(user.role))
      .input('Ativo', sql.Bit, user.active !== false)
      .input('AlgoritmoHashSenha', sql.NVarChar(30), user.passwordHash.algorithm)
      .input('SaltSenha', sql.VarBinary(64), Buffer.from(user.passwordHash.salt, 'base64'))
      .input('HashSenha', sql.VarBinary(128), Buffer.from(user.passwordHash.hash, 'base64'))
      .input('ParametrosHashSenha', sql.NVarChar(500), JSON.stringify(user.passwordHash.params))
      .input('CriadoEm', sql.DateTime2, toSqlDate(user.createdAt))
      .input('AtualizadoEm', sql.DateTime2, toSqlDate(user.updatedAt))
      .input('UltimoLoginEm', sql.DateTime2, toSqlDate(user.lastLoginAt))
      .query(`
        INSERT INTO ${sqlTables.users} (
          Id,
          Nome,
          Usuario,
          Perfil,
          Ativo,
          AlgoritmoHashSenha,
          SaltSenha,
          HashSenha,
          ParametrosHashSenha,
          CriadoEm,
          AtualizadoEm,
          UltimoLoginEm
        )
        VALUES (
          @Id,
          @Nome,
          @Usuario,
          @Perfil,
          @Ativo,
          @AlgoritmoHashSenha,
          @SaltSenha,
          @HashSenha,
          @ParametrosHashSenha,
          @CriadoEm,
          @AtualizadoEm,
          @UltimoLoginEm
        )
      `);
  }

  async function insertSqlEntry(transaction, entry) {
    await new sql.Request(transaction)
      .input('Id', sql.UniqueIdentifier, entry.id)
      .input('Titulo', sql.NVarChar(120), entry.title)
      .input('Login', sql.NVarChar(180), entry.login || null)
      .input('Url', sql.NVarChar(300), entry.url || null)
      .input('Categoria', sql.NVarChar(80), entry.category || null)
      .input('Observacoes', sql.NVarChar(sql.MAX), entry.notes || null)
      .input('AlgoritmoCriptografia', sql.NVarChar(50), entry.password.algorithm)
      .input('SenhaCriptografada', sql.VarBinary(sql.MAX), Buffer.from(entry.password.ciphertext, 'base64'))
      .input('VetorInicial', sql.VarBinary(12), Buffer.from(entry.password.iv, 'base64'))
      .input('TagAutenticacao', sql.VarBinary(16), Buffer.from(entry.password.tag, 'base64'))
      .input('CriadoPorUsuarioId', sql.UniqueIdentifier, entry.createdBy)
      .input('AtualizadoPorUsuarioId', sql.UniqueIdentifier, entry.updatedBy)
      .input('CriadoEm', sql.DateTime2, toSqlDate(entry.createdAt))
      .input('AtualizadoEm', sql.DateTime2, toSqlDate(entry.updatedAt))
      .query(`
        INSERT INTO ${sqlTables.entries} (
          Id,
          Titulo,
          Login,
          Url,
          Categoria,
          Observacoes,
          AlgoritmoCriptografia,
          SenhaCriptografada,
          VetorInicial,
          TagAutenticacao,
          CriadoPorUsuarioId,
          AtualizadoPorUsuarioId,
          CriadoEm,
          AtualizadoEm
        )
        VALUES (
          @Id,
          @Titulo,
          @Login,
          @Url,
          @Categoria,
          @Observacoes,
          @AlgoritmoCriptografia,
          @SenhaCriptografada,
          @VetorInicial,
          @TagAutenticacao,
          @CriadoPorUsuarioId,
          @AtualizadoPorUsuarioId,
          @CriadoEm,
          @AtualizadoEm
        )
      `);
  }

  async function insertSqlAudit(transaction, auditItem) {
    await new sql.Request(transaction)
      .input('Id', sql.UniqueIdentifier, auditItem.id)
      .input('UsuarioId', sql.UniqueIdentifier, auditItem.userId || null)
      .input('Usuario', sql.NVarChar(40), auditItem.username || null)
      .input('Acao', sql.NVarChar(80), auditItem.action)
      .input('RegistroAlvoId', sql.UniqueIdentifier, auditItem.targetId || null)
      .input('Resumo', sql.NVarChar(300), auditItem.summary || null)
      .input('CriadoEm', sql.DateTime2, toSqlDate(auditItem.at))
      .query(`
        INSERT INTO ${sqlTables.audit} (
          Id,
          UsuarioId,
          Usuario,
          Acao,
          RegistroAlvoId,
          Resumo,
          CriadoEm
        )
        VALUES (
          @Id,
          @UsuarioId,
          @Usuario,
          @Acao,
          @RegistroAlvoId,
          @Resumo,
          @CriadoEm
        )
      `);
  }

  function encryptSecret(secret, context) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
    cipher.setAAD(Buffer.from(context));
    const encrypted = Buffer.concat([
      cipher.update(String(secret), 'utf8'),
      cipher.final()
    ]);

    return {
      algorithm: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: encrypted.toString('base64')
    };
  }

  function decryptSecret(payload, context) {
    if (!payload || payload.algorithm !== 'aes-256-gcm') {
      throw new HttpError(500, 'Registro criptografado invalido.');
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      masterKey,
      Buffer.from(payload.iv, 'base64')
    );
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));

    return Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final()
    ]).toString('utf8');
  }

  async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('base64');
    const derived = await scrypt(password, salt, SCRYPT_PARAMS.keyLength, {
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p,
      maxmem: SCRYPT_PARAMS.maxmem
    });

    return {
      algorithm: 'scrypt',
      params: {
        N: SCRYPT_PARAMS.N,
        r: SCRYPT_PARAMS.r,
        p: SCRYPT_PARAMS.p,
        keyLength: SCRYPT_PARAMS.keyLength
      },
      salt,
      hash: derived.toString('base64')
    };
  }

  async function verifyPassword(password, stored) {
    if (!stored || stored.algorithm !== 'scrypt') {
      return false;
    }

    const derived = await scrypt(password, stored.salt, stored.params.keyLength, {
      N: stored.params.N,
      r: stored.params.r,
      p: stored.params.p,
      maxmem: SCRYPT_PARAMS.maxmem
    });
    const expected = Buffer.from(stored.hash, 'base64');

    return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
  }

  function serializeUser(user) {
    return {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
      active: user.active !== false,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt || null
    };
  }

  function serializeEntry(entry) {
    return {
      id: entry.id,
      title: entry.title,
      login: entry.login || '',
      url: entry.url || '',
      notes: entry.notes || '',
      category: entry.category || '',
      password: decryptSecret(entry.password, `entry:${entry.id}`),
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      createdBy: entry.createdBy,
      updatedBy: entry.updatedBy
    };
  }

  function addAudit(user, action, targetId, summary) {
    db.audit.unshift({
      id: crypto.randomUUID(),
      at: new Date().toISOString(),
      userId: user?.id || null,
      username: user?.username || 'sistema',
      action,
      targetId,
      summary
    });
    db.audit = db.audit.slice(0, 300);
  }

  function parseCookies(header = '') {
    return header.split(';').reduce((cookies, part) => {
      const index = part.indexOf('=');
      if (index === -1) {
        return cookies;
      }
      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (name) {
        cookies[name] = decodeURIComponent(value);
      }
      return cookies;
    }, {});
  }

  function makeCookie(name, value, options = {}) {
    const parts = [
      `${name}=${encodeURIComponent(value)}`,
      'HttpOnly',
      'SameSite=Strict',
      'Path=/'
    ];

    if (Number.isFinite(options.maxAge)) {
      parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
    }

    if (process.env.NODE_ENV === 'production' || process.env.APP_COOKIE_SECURE === 'true') {
      parts.push('Secure');
    }

    return parts.join('; ');
  }

  function createSession(user) {
    const sid = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sid, { userId: user.id, expiresAt });
    return {
      sid,
      cookie: makeCookie('sid', sid, { maxAge: SESSION_TTL_MS / 1000 })
    };
  }

  function destroySession(req) {
    const sid = parseCookies(req.headers.cookie || '').sid;
    if (sid) {
      sessions.delete(sid);
    }
  }

  function getAuthenticatedUser(req) {
    const sid = parseCookies(req.headers.cookie || '').sid;
    if (!sid) {
      return null;
    }

    const session = sessions.get(sid);
    if (!session || session.expiresAt <= Date.now()) {
      sessions.delete(sid);
      return null;
    }

    const user = db.users.find((candidate) => candidate.id === session.userId);
    if (!user || user.active === false) {
      sessions.delete(sid);
      return null;
    }

    session.expiresAt = Date.now() + SESSION_TTL_MS;
    return user;
  }

  function requireAuth(req) {
    const user = getAuthenticatedUser(req);
    if (!user) {
      throw new HttpError(401, 'Login necessario.');
    }
    return user;
  }

  function requireAdmin(user) {
    if (user.role !== 'admin') {
      throw new HttpError(403, 'Acesso restrito a administradores.');
    }
  }

  function getClientKey(req, username) {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'local';
    return `${ip}:${String(username || '').toLowerCase()}`;
  }

  function assertLoginAllowed(key) {
    const record = loginFailures.get(key);
    if (!record || Date.now() - record.firstAt > LOGIN_WINDOW_MS) {
      return;
    }
    if (record.count >= LOGIN_MAX_FAILURES) {
      throw new HttpError(429, 'Muitas tentativas. Aguarde alguns minutos e tente novamente.');
    }
  }

  function registerLoginFailure(key) {
    const current = loginFailures.get(key);
    if (!current || Date.now() - current.firstAt > LOGIN_WINDOW_MS) {
      loginFailures.set(key, { count: 1, firstAt: Date.now() });
      return;
    }
    current.count += 1;
  }

  function clearLoginFailures(key) {
    loginFailures.delete(key);
  }

  function requireText(body, field, label, options = {}) {
    const { min = 1, max = 255, trim = true } = options;
    const raw = body?.[field];
    const value = typeof raw === 'string' ? (trim ? raw.trim() : raw) : '';

    if (value.length < min || value.length > max) {
      throw new HttpError(400, `${label} deve ter entre ${min} e ${max} caracteres.`);
    }

    return value;
  }

  function optionalText(body, field, label, max = 255) {
    const raw = body?.[field];
    if (raw === undefined || raw === null) {
      return '';
    }

    const value = String(raw).trim();
    if (value.length > max) {
      throw new HttpError(400, `${label} deve ter no maximo ${max} caracteres.`);
    }
    return value;
  }

  function normalizeUsername(body) {
    const rawUsername = typeof body?.username === 'string' ? body.username : '';
    const username = rawUsername.trim().toLowerCase();
    if (username.length < 7 || username.length > 40) {
      throw new HttpError(
        400,
        `Usuario deve ter entre 7 e 40 caracteres. Atual: ${username.length}.`
      );
    }
    if (!/^[a-z0-9._-]+$/.test(username)) {
      throw new HttpError(400, 'Usuario aceita apenas letras, numeros, ponto, hifen e sublinhado.');
    }
    return username;
  }

  function requireValidSetupToken(body) {
    if (setupToken.length < 16) {
      throw new HttpError(403, 'Criacao inicial bloqueada. Configure APP_SETUP_TOKEN no .env com pelo menos 16 caracteres.');
    }

    const provided = String(body?.setupToken || '').trim();
    const expectedBuffer = Buffer.from(setupToken, 'utf8');
    const providedBuffer = Buffer.from(provided, 'utf8');
    const valid = expectedBuffer.length === providedBuffer.length
      && crypto.timingSafeEqual(expectedBuffer, providedBuffer);

    if (!valid) {
      throw new HttpError(403, 'Codigo de instalacao invalido.');
    }
  }

  function requireStrongPassword(body, field = 'password') {
    const password = requireText(body, field, 'Senha', { min: 8, max: 256, trim: false });
    if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      throw new HttpError(400, 'Senha precisa ter ao menos letras e numeros.');
    }
    return password;
  }

  function normalizeRole(role) {
    return role === 'admin' ? 'admin' : 'user';
  }

  async function createUser(body, creator, forcedRole = null) {
    const username = normalizeUsername(body);
    if (db.users.some((user) => user.username === username)) {
      throw new HttpError(409, 'Este usuario ja existe.');
    }

    const password = requireStrongPassword(body);
    const now = new Date().toISOString();
    const user = {
      id: crypto.randomUUID(),
      name: requireText(body, 'name', 'Nome', { min: 2, max: 80 }),
      username,
      role: forcedRole || normalizeRole(body.role),
      active: true,
      passwordHash: await hashPassword(password),
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null
    };

    db.users.push(user);
    addAudit(creator, 'user.create', user.id, `Usuario ${user.username} criado`);
    await saveDatabase();
    return user;
  }

  function createEntry(body, user) {
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    const password = requireText(body, 'password', 'Senha armazenada', {
      min: 1,
      max: 4096,
      trim: false
    });

    return {
      id,
      title: requireText(body, 'title', 'Titulo', { min: 1, max: 120 }),
      login: optionalText(body, 'login', 'Login', 180),
      url: optionalText(body, 'url', 'URL', 300),
      notes: optionalText(body, 'notes', 'Notas', 2000),
      category: optionalText(body, 'category', 'Categoria', 80),
      password: encryptSecret(password, `entry:${id}`),
      createdAt: now,
      updatedAt: now,
      createdBy: user.id,
      updatedBy: user.id
    };
  }

  function updateEntryFromBody(entry, body, user) {
    if (Object.hasOwn(body, 'title')) {
      entry.title = requireText(body, 'title', 'Titulo', { min: 1, max: 120 });
    }
    if (Object.hasOwn(body, 'login')) {
      entry.login = optionalText(body, 'login', 'Login', 180);
    }
    if (Object.hasOwn(body, 'url')) {
      entry.url = optionalText(body, 'url', 'URL', 300);
    }
    if (Object.hasOwn(body, 'notes')) {
      entry.notes = optionalText(body, 'notes', 'Notas', 2000);
    }
    if (Object.hasOwn(body, 'category')) {
      entry.category = optionalText(body, 'category', 'Categoria', 80);
    }
    if (Object.hasOwn(body, 'password')) {
      const password = requireText(body, 'password', 'Senha armazenada', {
        min: 1,
        max: 4096,
        trim: false
      });
      entry.password = encryptSecret(password, `entry:${entry.id}`);
    }

    entry.updatedAt = new Date().toISOString();
    entry.updatedBy = user.id;
  }

  async function parseJsonBody(req) {
    if (req.method === 'GET' || req.method === 'HEAD') {
      return {};
    }

    return new Promise((resolve, reject) => {
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        raw += chunk;
        if (Buffer.byteLength(raw) > JSON_LIMIT_BYTES) {
          reject(new HttpError(413, 'Requisicao muito grande.'));
          req.destroy();
        }
      });
      req.on('end', () => {
        if (!raw.trim()) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new HttpError(400, 'JSON invalido.'));
        }
      });
      req.on('error', reject);
    });
  }

  function sendJson(res, statusCode, payload, extraHeaders = {}) {
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    });
    res.end(JSON.stringify(payload));
  }

  function sendNoContent(res, extraHeaders = {}) {
    res.writeHead(204, {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    });
    res.end();
  }

  async function handleApi(req, res, pathname) {
    const body = await parseJsonBody(req);

    if (req.method === 'GET' && pathname === '/api/health') {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/setup') {
      sendJson(res, 200, { hasUsers: db.users.length > 0 });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/setup/first-admin') {
      if (db.users.length > 0) {
        throw new HttpError(409, 'Administrador inicial ja foi criado.');
      }

      requireValidSetupToken(body);
      const user = await createUser({ ...body, role: 'admin' }, null, 'admin');
      const session = createSession(user);
      user.lastLoginAt = new Date().toISOString();
      await saveDatabase();
      sendJson(res, 201, { user: serializeUser(user) }, { 'Set-Cookie': session.cookie });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/login') {
      const username = normalizeUsername(body);
      const key = getClientKey(req, username);
      assertLoginAllowed(key);

      const user = db.users.find((candidate) => candidate.username === username && candidate.active !== false);
      const password = requireText(body, 'password', 'Senha', { min: 1, max: 256, trim: false });
      const valid = user ? await verifyPassword(password, user.passwordHash) : false;

      if (!valid) {
        registerLoginFailure(key);
        throw new HttpError(401, 'Usuario ou senha invalidos.');
      }

      clearLoginFailures(key);
      const session = createSession(user);
      user.lastLoginAt = new Date().toISOString();
      addAudit(user, 'auth.login', user.id, 'Login realizado');
      await saveDatabase();
      sendJson(res, 200, { user: serializeUser(user) }, { 'Set-Cookie': session.cookie });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/logout') {
      const user = getAuthenticatedUser(req);
      destroySession(req);
      if (user) {
        addAudit(user, 'auth.logout', user.id, 'Logout realizado');
        await saveDatabase();
      }
      sendNoContent(res, { 'Set-Cookie': makeCookie('sid', '', { maxAge: 0 }) });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/me') {
      const user = requireAuth(req);
      sendJson(res, 200, { user: serializeUser(user) });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/vault') {
      requireAuth(req);
      const entries = db.entries
        .slice()
        .sort((a, b) => a.title.localeCompare(b.title, 'pt-BR'))
        .map(serializeEntry);
      sendJson(res, 200, { entries });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/vault') {
      const user = requireAuth(req);
      const entry = createEntry(body, user);
      db.entries.push(entry);
      addAudit(user, 'entry.create', entry.id, `Senha ${entry.title} criada`);
      await saveDatabase();
      sendJson(res, 201, { entry: serializeEntry(entry) });
      return;
    }

    const entryMatch = pathname.match(/^\/api\/vault\/([^/]+)$/);
    if (entryMatch && (req.method === 'PUT' || req.method === 'PATCH')) {
      const user = requireAuth(req);
      const entry = db.entries.find((candidate) => candidate.id === entryMatch[1]);
      if (!entry) {
        throw new HttpError(404, 'Senha nao encontrada.');
      }

      updateEntryFromBody(entry, body, user);
      addAudit(user, 'entry.update', entry.id, `Senha ${entry.title} atualizada`);
      await saveDatabase();
      sendJson(res, 200, { entry: serializeEntry(entry) });
      return;
    }

    if (entryMatch && req.method === 'DELETE') {
      const user = requireAuth(req);
      const index = db.entries.findIndex((candidate) => candidate.id === entryMatch[1]);
      if (index === -1) {
        throw new HttpError(404, 'Senha nao encontrada.');
      }

      const [removed] = db.entries.splice(index, 1);
      addAudit(user, 'entry.delete', removed.id, `Senha ${removed.title} excluida`);
      await saveDatabase();
      sendNoContent(res);
      return;
    }

    if (req.method === 'GET' && pathname === '/api/users') {
      const user = requireAuth(req);
      requireAdmin(user);
      sendJson(res, 200, { users: db.users.map(serializeUser) });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/users') {
      const user = requireAuth(req);
      requireAdmin(user);
      const created = await createUser(body, user);
      sendJson(res, 201, { user: serializeUser(created) });
      return;
    }

    const userMatch = pathname.match(/^\/api\/users\/([^/]+)$/);
    if (userMatch && req.method === 'DELETE') {
      const user = requireAuth(req);
      requireAdmin(user);
      const target = db.users.find((candidate) => candidate.id === userMatch[1]);

      if (!target) {
        throw new HttpError(404, 'Usuario nao encontrado.');
      }
      if (target.id === user.id) {
        throw new HttpError(400, 'Nao e possivel desativar o proprio usuario.');
      }

      target.active = false;
      target.updatedAt = new Date().toISOString();
      addAudit(user, 'user.disable', target.id, `Usuario ${target.username} desativado`);
      for (const [sid, session] of sessions.entries()) {
        if (session.userId === target.id) {
          sessions.delete(sid);
        }
      }
      await saveDatabase();
      sendJson(res, 200, { user: serializeUser(target) });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/audit') {
      const user = requireAuth(req);
      requireAdmin(user);
      sendJson(res, 200, { audit: db.audit.slice(0, 80) });
      return;
    }

    throw new HttpError(404, 'Rota nao encontrada.');
  }

  function contentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon'
    }[ext] || 'application/octet-stream';
  }

  async function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      throw new HttpError(405, 'Metodo nao permitido.');
    }

    const requested = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
    const filePath = path.resolve(publicDir, requested);
    const relative = path.relative(publicDir, filePath);

    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new HttpError(403, 'Caminho invalido.');
    }

    let stat;
    try {
      stat = await fsp.stat(filePath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new HttpError(404, 'Arquivo nao encontrado.');
      }
      throw error;
    }

    if (!stat.isFile()) {
      throw new HttpError(404, 'Arquivo nao encontrado.');
    }

    res.writeHead(200, {
      'Content-Type': contentType(filePath),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin'
    });

    if (req.method === 'HEAD') {
      res.end();
      return;
    }

    fs.createReadStream(filePath).pipe(res);
  }

  async function handler(req, res) {
    try {
      if (!db || !masterKey) {
        await init();
      }

      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) {
        await handleApi(req, res, url.pathname);
        return;
      }

      await serveStatic(req, res, url.pathname);
    } catch (error) {
      const statusCode = error instanceof HttpError ? error.statusCode : 500;
      if (!(error instanceof HttpError)) {
        console.error(error);
      }
      sendJson(res, statusCode, { error: error.message || 'Erro interno.' });
    }
  }

  async function listen(port = process.env.PORT || 3000, host = process.env.HOST || '127.0.0.1') {
    await init();
    const server = http.createServer(handler);
    await new Promise((resolve) => {
      server.listen(Number(port), host, resolve);
    });
    return server;
  }

  return {
    init,
    handler,
    listen
  };
}

if (require.main === module) {
  const app = createPasswordManagerServer();
  app.listen().then((server) => {
    const address = server.address();
    const host = address.address === '127.0.0.1' ? 'localhost' : address.address;
    console.log(`Gerenciador de senhas ativo em http://${host}:${address.port}`);
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  createPasswordManagerServer
};
