#!/usr/bin/env node
// genesis: the client CLI for a Genesis gateway. One file, Node.js 18 or newer,
// no dependencies. It stores the endpoint and personal key the user logs in
// with, drives the reviewed agent-auth-setup.sh installer for every client
// change, and talks to the gateway's bearer-authenticated CLI door
// (/admin/api/cli/*). Nothing privileged lives here: the server decides what a
// key may do from its role.
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import ttyModule from 'node:tty';
import { fileURLToPath, pathToFileURL } from 'node:url';

// A personal key: the s99dev. prefix and 20-512 URL-safe characters. Anything
// else is refused before it can reach a request, and no key bytes are echoed.
const KEY = /^s99dev\.[A-Za-z0-9_-]{20,512}$/;
const KEY_SHAPE = 'those start with s99dev. followed by 20-512 letters, digits, _ or -';
const ROLES = new Set(['owner', 'admin', 'viewer', 'client']);
const HTTP_TIMEOUT_MS = 30_000;
const LINK_POLL_MS = 2_000;
const LINK_LIMIT_MS = 10 * 60_000;
const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LINK_STATUSES = new Set(['starting', 'awaiting-browser', 'exchanging', 'done', 'failed', 'cancelled']);
const LINK_TERMINAL = new Set(['done', 'failed', 'cancelled']);
const PROFILE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[\x21-\x7e]{1,256}$/;
const PROVIDER_LABELS = { anthropic: 'Fable', 'openai-codex': 'Codex' };
const WINDOWS = ['today', '7d', '30d', 'all'];

// One row per supported client. `providers` are the gateway providers whose
// models the client can use; `binary` is what the installer requires on PATH.
export const CLIENTS = Object.freeze([
  { id: 'omp', label: 'OMP', binary: 'omp', providers: ['anthropic', 'openai-codex'] },
  { id: 'claude-code', label: 'Claude Code', binary: 'claude', providers: ['anthropic'] },
  { id: 'codex', label: 'Codex', binary: 'codex', providers: ['openai-codex'] },
  { id: 'opencode', label: 'OpenCode', binary: 'opencode', providers: ['anthropic', 'openai-codex'] },
  { id: 'pi', label: 'Pi', binary: 'pi', providers: ['anthropic', 'openai-codex'] },
]);

// ── errors ──────────────────────────────────────────────────────────────────
// Exit codes: 0 ok, 1 failure, 2 usage, 130 interrupted. An empty message
// means the reason was already printed (the installer reports its own).
export class CliError extends Error {
  constructor(message, exitCode = 1) { super(message); this.exitCode = exitCode; }
}
class HttpError extends CliError {
  constructor(status, message) { super(message); this.status = status; }
}
class Interrupt extends CliError {
  constructor() { super('', 130); }
}
const usage = message => new CliError(message, 2);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hostOf = endpoint => endpoint.replace(/^[a-z]+:\/\//, '');

// ── key hygiene ─────────────────────────────────────────────────────────────
// Every key this process has held is registered here; everything the CLI
// prints passes through redact(), which replaces those bytes with <key>.
const secrets = new Set();
function redact(text) {
  let value = String(text);
  for (const secret of secrets) value = value.split(secret).join('<key>');
  return value;
}
// True when TOKEN is a personal key; a well-formed key is registered for
// redaction. A malformed one is never registered, sent, or echoed.
function acceptKey(token) {
  if (typeof token !== 'string' || !KEY.test(token)) return false;
  secrets.add(token);
  return true;
}
// Before anything is printed, the exported AGENT_AUTH_TOKEN and the stored
// session key are registered, so a key pasted into the wrong prompt, typed
// into a URL or quoted by a child is rendered as <key>. Nothing is reported
// here; the command that needs the session explains what is wrong with it.
function primeSecrets() {
  acceptKey(process.env.AGENT_AUTH_TOKEN);
  let text = null;
  try { text = readSessionText(); } catch { return; }
  if (text === null) return;
  try { acceptKey(JSON.parse(text)?.token); } catch { /* loadSession reports */ }
}

// ── install layout ──────────────────────────────────────────────────────────
const here = path.dirname(fileURLToPath(import.meta.url));
const octal = mode => (mode & 0o777).toString(8).padStart(4, '0');
// release.json is trusted only when nobody else could have written it: opened
// without following a link and without blocking (a FIFO in its place is
// refused, never waited on), then judged by fstat as a regular file owned by
// this user that only this user may write, inside an install directory with
// the same properties. Absent (a source checkout) is null.
function releaseInfo() {
  const file = path.join(here, 'release.json');
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP') throw new CliError(`${file} must not be a symlink; remove it and rerun the published install line`);
    throw error;
  }
  let text;
  try {
    const directory = fs.statSync(here);
    if (directory.uid !== process.getuid()) throw new CliError(`${here} is not owned by this user; fix it and rerun the published install line`);
    if ((directory.mode & 0o022) !== 0) throw new CliError(`${here} must not be writable by others, found ${octal(directory.mode)}; run chmod 0755 on it`);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new CliError(`${file} is not a regular file; remove it and rerun the published install line`);
    if (stat.uid !== process.getuid()) throw new CliError(`${file} is not owned by this user; remove it and rerun the published install line`);
    if ((stat.mode & 0o022) !== 0) throw new CliError(`${file} must not be writable by others, found ${octal(stat.mode)}; run chmod 0644 on it`);
    text = fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
  let value;
  try { value = JSON.parse(text); } catch { throw new CliError(`${file} is not valid JSON; rerun the published install line`); }
  if (!record(value)) throw new CliError(`${file} is not a release record; rerun the published install line`);
  return value;
}
// Installed: beside genesis.mjs. Source checkout: the assembled artifact one directory up.
function setupScript() {
  for (const candidate of [path.join(here, 'agent-auth-setup.sh'), path.join(here, '..', 'agent-auth-setup.sh')]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new CliError('agent-auth-setup.sh is missing beside genesis.mjs; run genesis update');
}

// ── session store ───────────────────────────────────────────────────────────
// ${XDG_CONFIG_HOME:-~/.config}/genesis/session.json (0600, dir 0700) holds
// {version, endpoint, name, role, email, token, updatedAt}, replaced by rename.
export function configDir() {
  const xdg = process.env.XDG_CONFIG_HOME;
  return path.join(xdg && path.isAbsolute(xdg) ? xdg : path.join(os.homedir(), '.config'), 'genesis');
}
export const sessionFile = () => path.join(configDir(), 'session.json');
// The directory must be a real directory owned by this user, mode exactly
// 0700; null when absent.
function checkSessionDir(directory) {
  let stat;
  try { stat = fs.lstatSync(directory); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new CliError(`${directory} must be a directory, not a symlink; fix it and run genesis login`);
  if (stat.uid !== process.getuid()) throw new CliError(`${directory} is not owned by this user; fix it and run genesis login`);
  if ((stat.mode & 0o777) !== 0o700) throw new CliError(`${directory} must be mode 0700, found ${octal(stat.mode)}; run chmod 0700 on it`);
  return stat;
}
function refuseSymlink(file) {
  let stat;
  try { stat = fs.lstatSync(file); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (stat.isSymbolicLink()) throw new CliError(`${file} must not be a symlink`);
}
function readPrivate(file) {
  refuseSymlink(file);
  try { return fs.readFileSync(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
// Opened without following a link and without blocking (a FIFO in its place
// is refused, never waited on), then judged by fstat: a regular file, owned
// by this user, mode exactly 0600. Anything else is refused in one line.
function readSessionText() {
  const file = sessionFile();
  if (checkSessionDir(path.dirname(file)) === null) return null;
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP') throw new CliError(`${file} must not be a symlink; remove it and run genesis login`);
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new CliError(`${file} is not a regular file; remove it and run genesis login`);
    if (stat.uid !== process.getuid()) throw new CliError(`${file} is not owned by this user; remove it and run genesis login`);
    if ((stat.mode & 0o777) !== 0o600) throw new CliError(`${file} must be mode 0600, found ${octal(stat.mode)}; run chmod 0600 on it or genesis login`);
    return fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
}
// Created 0600 under a 0700 directory owned by this user, then renamed into place.
function writeSessionText(text) {
  const file = sessionFile();
  const directory = path.dirname(file);
  if (checkSessionDir(directory) === null) { fs.mkdirSync(directory, { recursive: true, mode: 0o700 }); fs.chmodSync(directory, 0o700); }
  refuseSymlink(file);
  const temporary = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try { fs.writeFileSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}
export function loadSession() {
  const text = readSessionText();
  if (text === null) return null;
  const file = sessionFile();
  let value;
  try { value = JSON.parse(text); } catch { throw new CliError(`${file} is not valid JSON; run genesis login`); }
  if (!record(value) || value.version !== 1 || typeof value.endpoint !== 'string' || typeof value.name !== 'string'
    || !ROLES.has(value.role) || (value.email !== null && typeof value.email !== 'string') || typeof value.token !== 'string') {
    throw new CliError(`${file} is not a genesis session; run genesis login`);
  }
  if (!acceptKey(value.token)) throw new CliError(`${file} does not hold a personal gateway key; run genesis login`);
  return { endpoint: value.endpoint, name: value.name, role: value.role, email: value.email, token: value.token };
}
function saveSession(session) {
  writeSessionText(JSON.stringify({
    version: 1, endpoint: session.endpoint, name: session.name, role: session.role, email: session.email,
    token: session.token, updatedAt: new Date().toISOString(),
  }, null, 2) + '\n');
}
// logout removes the session file and nothing else; a link in its place is refused.
function clearSession() {
  const file = sessionFile();
  if (checkSessionDir(path.dirname(file)) === null) return;
  refuseSymlink(file);
  fs.rmSync(file, { force: true });
}
function requireSession() {
  const session = loadSession();
  if (session === null) throw new CliError('not logged in; run genesis login');
  return session;
}

// ── endpoint ────────────────────────────────────────────────────────────────
// Same rules as the installer: a bare host means HTTPS; cleartext HTTP only on loopback.
export function normalizeEndpoint(input) {
  let value = String(input ?? '').trim();
  if (value === '') return { error: 'enter the gateway host or URL, for example gateway.example.com' };
  if (/\s/.test(value)) return { error: 'the gateway URL must not contain spaces' };
  if (!value.includes('://')) value = `https://${value}`;
  value = value.replace(/\/+$/, '');
  if (value.includes('?') || value.includes('#')) return { error: 'the gateway URL must not contain a query or fragment' };
  const secure = /^https:\/\/([^/]+)(\/.*)?$/.exec(value);
  if (secure !== null) {
    if (secure[1].includes('@')) return { error: 'the gateway URL must not contain credentials' };
    return { value };
  }
  if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(\/.*)?$/.test(value)) return { value };
  if (value.startsWith('http://')) return { error: 'cleartext http:// is accepted only for localhost; use https://' };
  return { error: 'use https://HOST (or a bare host); other schemes are not gateways' };
}

// ── HTTP ────────────────────────────────────────────────────────────────────
function reasonOf(error) {
  if (error?.name === 'TimeoutError') return `timed out after ${HTTP_TIMEOUT_MS / 1000} s`;
  const cause = error?.cause;
  if (typeof cause?.code === 'string') return cause.code;
  return String(cause?.message ?? error?.message ?? error);
}
// JSON in, JSON out. Failures become one line naming the host and the server's
// `error`; a bearer is sent only when it is a personal key, and its bytes are
// redacted from every rendered line.
async function request(endpoint, token, method, pathname, body, timeoutMs = HTTP_TIMEOUT_MS) {
  const headers = { Accept: 'application/json' };
  if (token !== null) {
    if (!acceptKey(token)) throw new CliError(`the stored key is not a personal gateway key (${KEY_SHAPE}); run genesis login`);
    headers.Authorization = `Bearer ${token}`;
  }
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(`${endpoint}${pathname}`, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new CliError(`could not reach ${hostOf(endpoint)}: ${reasonOf(error)}`);
  }
  if (Number(response.headers.get('content-length') ?? 0) > 4 * 1024 * 1024) {
    throw new CliError(`${hostOf(endpoint)}: response too large for ${pathname}`);
  }
  const text = await response.text();
  let value = null;
  try { value = text === '' ? null : JSON.parse(text); } catch { value = null; }
  if (!response.ok) {
    const detail = typeof value?.error === 'string' ? value.error : `unexpected ${response.status} response`;
    throw new HttpError(response.status, `${hostOf(endpoint)}: ${detail} (HTTP ${response.status})`);
  }
  return value;
}
const api = (session, method, pathname, body, timeoutMs) => request(session.endpoint, session.token, method, pathname, body, timeoutMs);

// ── terminal ────────────────────────────────────────────────────────────────
const utf8 = /utf-?8/i.test(process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || '');
const glyph = utf8 ? { ok: '✓', pick: '❯', step: '›', dot: '·' } : { ok: '+', pick: '>', step: '>', dot: '.' };
const ansi = () => process.env.TERM !== 'dumb';
const colorOut = () => process.stdout.isTTY === true && ansi() && !process.env.NO_COLOR;
const paint = (code, text, enabled = colorOut()) => (enabled ? `\x1b[${code}m${text}\x1b[0m` : text);
const out = text => { process.stdout.write(`${redact(text)}\n`); };
const note = text => out(`${glyph.step} ${text}`);
const done = (label, value) => out(`${paint('32', glyph.ok)} ${label.padEnd(9)} ${value}`);
const warn = text => out(`${paint('33', '!')} ${text}`);
// Child output (the installer) is relayed line by line through redact():
// bytes are held until their newline arrives, so a key split across two
// chunks is still caught, and the remainder is flushed when the stream
// closes. latin1 maps every byte to one character and back, so nothing else
// about the child's bytes changes.
function relay(source, target) {
  let held = '';
  source.setEncoding('latin1');
  source.on('data', chunk => {
    held += chunk;
    const cut = held.lastIndexOf('\n') + 1;
    if (cut === 0) return;
    target.write(redact(held.slice(0, cut)), 'latin1');
    held = held.slice(cut);
  });
  source.on('close', () => { if (held !== '') target.write(redact(held), 'latin1'); });
}

let terminal = null;
function tty() {
  if (terminal !== null) return terminal;
  let fd;
  try { fd = fs.openSync('/dev/tty', 'r+'); } catch { return null; }
  const input = new ttyModule.ReadStream(fd);
  const output = new ttyModule.WriteStream(fd);
  input.pause();
  terminal = { input, output, cursorHidden: false, raw: false };
  return terminal;
}
// Prompts need a terminal for output and /dev/tty for input; stdin may be a pipe.
export const interactive = () => process.stdout.isTTY === true && tty() !== null;
const colorTty = () => ansi() && !process.env.NO_COLOR;
const tint = (code, text) => paint(code, text, colorTty());
// The one way anything reaches the terminal: prompts, echoes, menus and
// summaries all pass through redact() like stdout does.
const term = text => { tty().output.write(redact(text)); };
function restoreTerminal() {
  if (terminal === null) return;
  if (terminal.cursorHidden) { term('\x1b[?25h'); terminal.cursorHidden = false; }
  if (terminal.raw) { terminal.input.setRawMode(false); terminal.raw = false; }
  terminal.input.pause();
}
function closeTerminal() {
  if (terminal === null) return;
  restoreTerminal();
  terminal.input.destroy();
  terminal = null;
}
function readChunk() {
  const { input } = tty();
  input.setRawMode(true);
  terminal.raw = true;
  input.resume();
  return new Promise(resolve => {
    input.once('data', chunk => {
      input.pause();
      input.setRawMode(false);
      terminal.raw = false;
      resolve(chunk.toString('utf8'));
    });
  });
}
// One line from the terminal in raw mode: no echo when hidden, backspace and
// Ctrl-U edit, Ctrl-C interrupts, escape sequences (arrows) are ignored.
async function readLine(hidden) {
  let line = '';
  for (;;) {
    const chunk = await readChunk();
    if (chunk.startsWith('\x1b')) continue;
    for (const char of chunk) {
      if (char === '\r' || char === '\n') { term('\n'); return line; }
      if (char === '\x03') { term('\n'); throw new Interrupt(); }
      if (char === '\x04' && line === '') { term('\n'); throw new CliError('cancelled', 1); }
      if (char === '\x7f' || char === '\b') {
        if (line !== '') { line = line.slice(0, -1); if (!hidden) term('\b \b'); }
        continue;
      }
      if (char === '\x15') { if (!hidden) term('\b \b'.repeat(line.length)); line = ''; continue; }
      if (char < ' ') continue;
      line += char;
      if (!hidden) term(char);
    }
  }
}
const columns = () => tty()?.output.columns || 80;
const summary = (label, value) => term(`${tint('32', glyph.ok)} ${label.padEnd(9)} ${value}\n`);
// ask(label, validate): validate returns {value} or {error}; the typed line is
// replaced by a one-line summary once accepted.
async function ask(label, validate, summaryLabel = label) {
  for (;;) {
    const prompt = `? ${label} ${glyph.step} `;
    term(`${tint('36', '?')} ${tint('1', label)} ${glyph.step} `);
    const line = await readLine(false);
    const result = validate(line);
    if (result.error === undefined) {
      if (ansi()) term(`\x1b[${Math.floor((prompt.length + line.length) / columns()) + 1}A\x1b[J`);
      summary(summaryLabel, result.value);
      return result.value;
    }
    term(`${tint('33', '!')} ${result.error}\n`);
  }
}
async function secret(label, summaryLabel) {
  for (;;) {
    term(`${tint('36', '?')} ${tint('1', label)} ${tint('2', '(hidden)')} ${glyph.step} `);
    const line = await readLine(true);
    if (line === '') { term(`${tint('33', '!')} nothing was entered\n`); continue; }
    if (/\s/.test(line)) { term(`${tint('33', '!')} a key is one word with no spaces\n`); continue; }
    if (ansi()) term('\x1b[1A\x1b[J');
    summary(summaryLabel, 'received');
    return line;
  }
}
async function confirm(question, defaultYes = false) {
  for (;;) {
    term(`${tint('36', '?')} ${question} ${tint('2', defaultYes ? '(Y/n)' : '(y/N)')} ${glyph.step} `);
    const line = (await readLine(false)).trim().toLowerCase();
    if (line === '') return defaultYes;
    if (['y', 'yes'].includes(line)) return true;
    if (['n', 'no'].includes(line)) return false;
    term(`${tint('33', '!')} answer y or n\n`);
  }
}
// select(label, [{value, label, hint}], defaultIndex) -> value. Arrow keys, j/k
// or a digit move the highlight; Enter confirms. Without ANSI (TERM=dumb or a
// pane too narrow to redraw in place) a numbered prompt is used instead.
async function select(label, options, defaultIndex = 0) {
  const width = Math.max(...options.map(option => option.label.length));
  let selected = Math.max(0, Math.min(defaultIndex, options.length - 1));
  const finish = () => { summary(label, options[selected].label); return options[selected].value; };
  if (!ansi() || columns() < width + 6) {
    term(`? ${label}\n`);
    options.forEach((option, index) => term(`  ${index + 1}) ${option.label}${option.hint ? `  ${option.hint}` : ''}\n`));
    for (;;) {
      term(`Choice [1-${options.length}, default ${selected + 1}]: `);
      const line = (await readLine(false)).trim();
      if (line === '') return finish();
      if (/^[0-9]+$/.test(line) && Number(line) >= 1 && Number(line) <= options.length) { selected = Number(line) - 1; return finish(); }
      term(`Enter a number from 1 to ${options.length}.\n`);
    }
  }
  term('\x1b[?25l');
  terminal.cursorHidden = true;
  term(`${tint('36', '?')} ${tint('1', label)}\n`);
  try {
    for (;;) {
      const room = columns() - width - 8;
      options.forEach((option, index) => {
        let hint = option.hint ?? '';
        if (room < 4) hint = '';
        else if (hint.length > room) hint = `${hint.slice(0, room - 1)}…`;
        const text = index === selected
          ? `  ${tint('36', `${glyph.pick} ${option.label.padEnd(width)}`)}  ${tint('2', hint)}`
          : `    ${option.label.padEnd(width)}  ${tint('2', hint)}`;
        term(`${text}\x1b[K\n`);
      });
      const key = await readChunk();
      if (key === '\r' || key === '\n') break;
      if (key === '\x03') { term(`\x1b[${options.length + 1}A\x1b[J`); throw new Interrupt(); }
      if (key === 'k' || key === 'K' || key === '\x1b[A' || key === '\x1bOA') selected = (selected + options.length - 1) % options.length;
      else if (key === 'j' || key === 'J' || key === '\x1b[B' || key === '\x1bOB') selected = (selected + 1) % options.length;
      else if (/^[1-9]$/.test(key) && Number(key) <= options.length) selected = Number(key) - 1;
      term(`\x1b[${options.length}A`);
    }
    term(`\x1b[${options.length + 1}A\x1b[J`);
  } finally {
    term('\x1b[?25h');
    terminal.cursorHidden = false;
  }
  return finish();
}
// Aligned columns, two spaces apart; `right` marks right-aligned columns.
export function table(header, rows, right = new Set()) {
  const widths = header.map((cell, column) => Math.max(cell.length, ...rows.map(row => String(row[column]).length)));
  const line = (row, dim) => row.map((cell, column) => {
    const text = String(cell);
    const padded = right.has(column) ? text.padStart(widths[column]) : text.padEnd(widths[column]);
    return dim ? paint('2', padded) : padded;
  }).join('  ').replace(/\s+$/, '');
  return [line(header, true), ...rows.map(row => line(row, false))].join('\n');
}
const amount = value => value.toLocaleString('en-US', { maximumFractionDigits: 2 });
const integer = value => Math.round(value).toLocaleString('en-US');
const percent = fraction => `${(fraction * 100).toLocaleString('en-US', { maximumFractionDigits: 1 })}%`;
export function countdown(untilMs, nowMs = Date.now()) {
  if (!Number.isFinite(untilMs)) return '—';
  const total = Math.max(0, Math.round((untilMs - nowMs) / 60_000));
  if (total === 0) return 'now';
  const days = Math.floor(total / 1440), hours = Math.floor((total % 1440) / 60), minutes = total % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// ── clients and scopes ──────────────────────────────────────────────────────
function clientById(id) {
  const client = CLIENTS.find(entry => entry.id === id);
  if (client === undefined) throw usage(`unknown client ${id}; use ${CLIENTS.map(entry => entry.id).join(', ')}`);
  return client;
}
function installed(binary) {
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    if (directory === '') continue;
    const candidate = path.join(directory, binary);
    try { fs.accessSync(candidate, fs.constants.X_OK); if (fs.statSync(candidate).isFile()) return true; } catch { /* next entry */ }
  }
  return false;
}
const homeDir = (name, fallback) => {
  const value = process.env[name];
  return value && path.isAbsolute(value) ? value : path.join(os.homedir(), fallback);
};
const exists = file => { try { fs.lstatSync(file); return true; } catch { return false; } };
const isDirectory = file => { try { return fs.statSync(file).isDirectory(); } catch { return false; } };
// The installer's resolve_config_directory: the real path of the nearest
// existing ancestor plus the missing tail, so a scope under a linked directory
// names one physical place.
function realDirectory(directory) {
  let parent = directory;
  let suffix = '';
  while (!isDirectory(parent)) {
    suffix = `/${path.basename(parent)}${suffix}`;
    parent = path.dirname(parent);
  }
  return `${fs.realpathSync(parent)}${suffix}`;
}
// The installer's resolve_config_target: a linked config file is followed to
// its real path (at most 16 hops) and must be a regular file or absent.
function resolveConfigTarget(file) {
  if (!path.isAbsolute(file) || /[\t\r\n]/.test(file)) throw new CliError('config path must be one absolute path');
  let current = file;
  for (let hops = 0; ; hops++) {
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
    if (!stat.isSymbolicLink()) {
      if (!stat.isFile()) throw new CliError(`config is not a regular file: ${current}`);
      break;
    }
    if (hops >= 16) throw new CliError('config has a symlink loop');
    const target = fs.readlinkSync(current);
    current = path.isAbsolute(target) ? target : path.join(fs.realpathSync(path.dirname(current)), target);
  }
  return path.join(realDirectory(path.dirname(current)), path.basename(current));
}
// The same path rules as the installer: each client's own environment picks
// the scope; OMP answers through its own CLI. `targets` are the files whose
// presence means consent is needed before a configure replaces them.
function resolveScope(client, profile) {
  if (client.id === 'omp') {
    const result = spawnSync('omp', [...(profile ? ['--profile', profile] : []), 'config', 'path'],
      { encoding: 'utf8', timeout: 20_000, stdio: ['ignore', 'pipe', 'pipe'] });
    const agentDir = (result.stdout ?? '').trim();
    if (result.status !== 0 || !path.isAbsolute(agentDir) || agentDir.includes('\n')) throw new CliError('omp config path did not return one absolute path');
    const tokenDir = path.join(agentDir, 'agent-auth');
    return { stateFile: path.join(tokenDir, 'switch.json'), targets: [path.join(agentDir, 'models.yml'), path.join(agentDir, 'config.yml'), path.join(tokenDir, 'token')] };
  }
  if (client.id === 'claude-code') {
    const directory = homeDir('CLAUDE_CONFIG_DIR', '.claude');
    return { stateFile: path.join(directory, 'agent-auth/switch.json'), targets: [path.join(directory, 'settings.json'), path.join(directory, 'agent-auth/token')] };
  }
  if (client.id === 'codex') {
    const directory = homeDir('CODEX_HOME', '.codex');
    const tokenDir = path.join(directory, 'agent-auth', profile ?? 'default');
    return {
      stateFile: path.join(tokenDir, 'switch.json'),
      targets: [path.join(directory, profile ? `${profile}.config.toml` : 'config.toml'), path.join(tokenDir, 'token'), path.join(tokenDir, 'models.json')],
    };
  }
  if (client.id === 'opencode') {
    // adapters/opencode.sh: an explicit OPENCODE_CONFIG, else the first present
    // (or linked) candidate; the key and state live beside the real config file.
    const directory = path.join(homeDir('XDG_CONFIG_HOME', '.config'), 'opencode');
    const explicit = process.env.OPENCODE_CONFIG;
    const config = resolveConfigTarget(explicit
      ? explicit
      : ['opencode.jsonc', 'opencode.json', 'config.json'].map(name => path.join(directory, name)).find(exists) ?? path.join(directory, 'opencode.json'));
    const tokenDir = path.join(path.dirname(config), 'agent-auth');
    return { stateFile: path.join(tokenDir, 'switch.json'), targets: [config, path.join(tokenDir, 'token')] };
  }
  const directory = homeDir('PI_CODING_AGENT_DIR', '.pi/agent');
  return { stateFile: path.join(directory, 'agent-auth/switch.json'), targets: [path.join(directory, 'models.json'), path.join(directory, 'settings.json'), path.join(directory, 'agent-auth/token')] };
}
// Codex keeps one private directory per profile; every switch state under it
// is a scope of its own. Other clients answer for the default scope only.
function codexProfiles() {
  const root = path.join(homeDir('CODEX_HOME', '.codex'), 'agent-auth');
  let names;
  try { names = fs.readdirSync(root); } catch { return []; }
  return names.filter(name => name !== 'default' && PROFILE.test(name) && exists(path.join(root, name, 'switch.json'))).sort();
}
const fieldAt = (state, role, keys) => {
  for (const file of Array.isArray(state.files) ? state.files : []) {
    if (file.role !== role || !Array.isArray(file.fields)) continue;
    const field = file.fields.find(entry => Array.isArray(entry.path) && entry.path.length === keys.length && entry.path.every((key, index) => key === keys[index]));
    if (field?.gateway?.present === true && typeof field.gateway.value === 'string') return field.gateway.value;
  }
  return null;
};
// The switch state the installer writes beside the key: mode, issuing gateway,
// and the gateway-owned fields (the client's default model among them).
export function readState(file, clientId) {
  const text = readPrivate(file);
  if (text === null) return null;
  let state;
  try { state = JSON.parse(text); } catch { throw new CliError(`${file} is not valid JSON`); }
  if (!record(state) || state.version !== 1 || !['enabled', 'disabled'].includes(state.mode)) throw new CliError(`${file} is not a switch state this CLI understands`);
  let model = null;
  if (clientId === 'omp') model = fieldAt(state, 'settings', ['modelRoles', 'default']);
  else if (clientId === 'pi') {
    const id = fieldAt(state, 'settings', ['defaultModel']);
    const provider = fieldAt(state, 'settings', ['defaultProvider']);
    model = id === null ? null : provider === null ? id : `${provider.replace(/^agent-auth-/, '')}/${id}`;
  } else model = fieldAt(state, 'config', ['model'])?.replace(/^agent-auth-/, '') ?? null;
  return { mode: state.mode, gateway: typeof state.gateway === 'string' ? state.gateway : null, model };
}
// connected | disabled | not configured | foreign gateway | not installed
export function scopeStatus(state, isInstalled, endpoint) {
  if (state === null) return isInstalled ? 'not configured' : 'not installed';
  if (state.gateway !== endpoint) return 'foreign gateway';
  return state.mode === 'enabled' ? 'connected' : 'disabled';
}
// One row per scope. `problem` is set when the scope could not be discovered
// (for example `omp config path` failed); such a scope is reported, never
// treated as absent.
function statusRows(session, profile) {
  const rows = [];
  for (const client of CLIENTS) {
    const profiles = client.id === 'codex' ? [profile ?? '', ...codexProfiles().filter(name => name !== profile)] : [client.id === 'omp' ? profile ?? '' : ''];
    for (const scopeProfile of profiles) {
      const isInstalled = installed(client.binary);
      let state = null, problem = null;
      try {
        if (client.id !== 'omp' || isInstalled) state = readState(resolveScope(client, scopeProfile || undefined).stateFile, client.id);
      } catch (error) { problem = error.message; }
      rows.push({
        client, profile: scopeProfile, state, installed: isInstalled, problem,
        status: problem ?? scopeStatus(state, isInstalled, session.endpoint),
        label: scopeProfile ? `${client.label} (${scopeProfile})` : client.label,
      });
    }
  }
  return rows;
}
export function renderStatus(rows) {
  return table(['client', 'installed', 'state', 'model', 'gateway'], rows.map(row => [
    row.label, row.installed ? 'yes' : 'no', row.status, row.state?.model ?? '—', row.state?.gateway ? hostOf(row.state.gateway) : '—',
  ]));
}
const header = session => out(paint('1', `${session.endpoint} ${glyph.dot} ${session.name} ${glyph.dot} ${session.role}`));

// ── installer ───────────────────────────────────────────────────────────────
// AGENT_AUTH_URL/AGENT_AUTH_TOKEN carry the session into the installer; the key
// never appears on a command line. Its output is relayed through the redactor;
// its prompts, when any, come from /dev/tty, which it opens itself.
async function runSetup(session, client, action, args, withToken) {
  const env = { ...process.env, AGENT_AUTH_URL: session.endpoint };
  delete env.AUTH_GATEWAY_TOKEN;
  delete env.AGENT_AUTH_KEY_CHOICE;
  delete env.AGENT_AUTH_TOKEN;
  if (withToken) env.AGENT_AUTH_TOKEN = session.token;
  const child = spawn('bash', [setupScript(), '--harness', client.id, '--action', action, '--unattended', ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  relay(child.stdout, process.stdout);
  relay(child.stderr, process.stderr);
  const [code, signal] = await once(child, 'close');
  if (code === 0) return;
  if (signal === 'SIGINT' || code === 130) throw new Interrupt();
  throw new CliError(code === 1 ? '' : `setup exited ${code ?? signal}`);
}
const profileArgs = profile => (profile ? ['--profile', profile] : []);
function checkProfile(client, profile) {
  if (profile === undefined) return;
  if (!PROFILE.test(profile)) throw usage('profile names are [a-z0-9][a-z0-9._-]{0,63}');
  if (!['omp', 'codex'].includes(client.id)) throw usage('--profile is only supported by OMP and Codex');
}
// Consent before --overwrite: OMP always (its scope lookup may initialize client
// state); other clients only when the scope already holds a config or key.
async function consentToOverwrite(client, profile, flags) {
  if (flags.overwrite) return true;
  let occupied = client.id === 'omp';
  if (!occupied) {
    try { const scope = resolveScope(client, profile); occupied = [scope.stateFile, ...scope.targets].some(exists); } catch { occupied = true; }
  }
  if (!occupied) return false;
  if (!interactive()) {
    throw usage(client.id === 'omp' ? 'OMP setup needs --overwrite without a terminal (its scope lookup may initialize client state)'
      : `${client.label} is already set up here; add --overwrite to replace its gateway settings and key`);
  }
  const question = client.id === 'omp'
    ? 'Set up OMP here? Existing gateway settings and key in this scope are replaced; OMP may initialize its state'
    : `Replace the ${client.label} gateway settings and key in this scope? Unrelated settings stay intact`;
  if (await confirm(question)) return true;
  out(`Left ${client.label} alone; no user files changed.`);
  return null;
}
async function configure(session, client, flags) {
  checkProfile(client, flags.profile);
  if (flags.model !== undefined && !MODEL_ID.test(flags.model)) throw usage('model ids are 1-256 printable ASCII characters without spaces');
  const overwrite = await consentToOverwrite(client, flags.profile, flags);
  if (overwrite === null) return false;
  await runSetup(session, client, 'configure', [
    '--new-key', ...(overwrite ? ['--overwrite'] : []), ...(flags.model !== undefined ? ['--model', flags.model] : []), ...profileArgs(flags.profile),
  ], true);
  return true;
}
async function switchScope(session, client, action, flags) {
  checkProfile(client, flags.profile);
  await runSetup(session, client, action, profileArgs(flags.profile), false);
}

// ── served models ───────────────────────────────────────────────────────────
// /v1/models lists provider-qualified ids; clients take the raw provider id
// (request_model_id when the gateway names one), OMP its own provider/id selector.
export function servedModels(catalog, client) {
  if (!record(catalog) || !Array.isArray(catalog.data)) throw new CliError('the gateway model catalog is not in the expected shape');
  const models = [];
  for (const card of catalog.data) {
    if (!record(card) || typeof card.id !== 'string' || !client.providers.includes(card.owned_by)) continue;
    const suffix = card.id.startsWith(`${card.owned_by}/`) ? card.id.slice(card.owned_by.length + 1) : card.id;
    const id = client.id !== 'omp' && typeof card.request_model_id === 'string' ? card.request_model_id : suffix;
    if (!MODEL_ID.test(id)) continue;
    models.push({ id, provider: card.owned_by, name: typeof card.display_name === 'string' ? card.display_name : id });
  }
  if (models.length === 0) throw new CliError(`the gateway serves no models for ${client.label}`);
  return models;
}
export function renderModels(models, current) {
  return table(['model', 'provider', 'name', ''], models.map(model => [
    model.id, model.provider, model.name, current !== null && model.id === current ? 'current' : '',
  ]));
}
// The raw provider id of a saved selector: the provider prefix and an OMP
// effort suffix (anthropic/claude-haiku-4-5:low) are not part of the id.
export const rawModelId = selector => selector.slice(selector.lastIndexOf('/') + 1).split(':')[0];
const currentModelId = state => (state?.model ? rawModelId(state.model) : null);

// ── renderers ───────────────────────────────────────────────────────────────
const number = value => (typeof value === 'number' && Number.isFinite(value) ? value : null);
const bars = value => (number(value) === null ? '—' : value.toFixed(2));
export function renderUsage(payload) {
  if (!record(payload) || !Array.isArray(payload.barTypes) || !record(payload.windows)
    || WINDOWS.some(key => !record(payload.windows[key]) || !record(payload.windows[key].tokens) || !record(payload.windows[key].bars))) {
    throw new CliError('the usage payload is not in the expected shape');
  }
  const types = payload.barTypes.filter(type => record(type) && typeof type.id === 'string' && typeof type.label === 'string');
  const rows = WINDOWS.map(key => {
    const window = payload.windows[key];
    // null counters mean the gateway's recorder checkpoint is unreadable, not an idle account.
    const count = value => (number(value) === null ? '—' : integer(value));
    return [key, ...types.map(type => bars(window.bars[type.id])), count(window.calls),
      ...['input', 'output', 'cacheRead', 'cacheWrite'].map(field => count(window.tokens[field]))];
  });
  const head = ['window', ...types.map(type => `${type.label} bars`), 'calls', 'input', 'output', 'cache read', 'cache write'];
  return table(head, rows, new Set(head.map((_, index) => index).slice(1)));
}
export function renderCapacity(payload, nowMs = Date.now()) {
  if (!record(payload) || !Array.isArray(payload.providers)) throw new CliError('the capacity payload is not in the expected shape');
  const rows = [];
  for (const provider of payload.providers) {
    if (!record(provider)) continue;
    const label = typeof provider.label === 'string' ? provider.label : String(provider.id);
    const eligible = number(provider.eligible) === null ? '—' : `${provider.eligible} / ${number(provider.accounts) ?? '—'}`;
    const reset = countdown(provider.nextResetMs, nowMs);
    const metrics = provider.unavailable === true || !Array.isArray(provider.metrics) ? [] : provider.metrics.filter(record);
    if (metrics.length === 0) { rows.push([label, 'unavailable', '—', '—', eligible, reset]); continue; }
    metrics.forEach((metric, index) => {
      const known = metric.known === true && number(metric.used) !== null && number(metric.total) !== null;
      rows.push([
        index === 0 ? label : '', String(metric.label ?? metric.id),
        `${known ? amount(metric.used) : '—'} / ${number(metric.total) === null ? '—' : amount(metric.total)}`,
        known && number(metric.fill) !== null ? percent(metric.fill) : '—',
        index === 0 ? eligible : '', index === 0 ? reset : '',
      ]);
    });
  }
  return table(['provider', 'metric', 'bars', 'next bar', 'eligible', 'reset'], rows, new Set([2, 3]));
}
export function renderConnections(payload, nowMs = Date.now()) {
  if (!record(payload) || !Array.isArray(payload.connections)) throw new CliError('the connections payload is not in the expected shape');
  const rows = payload.connections.filter(record).map(connection => [
    PROVIDER_LABELS[connection.provider] ?? String(connection.provider),
    connection.email ?? '—',
    [...new Set([connection.plan, connection.kind].filter(value => typeof value === 'string' && value !== ''))].join(` ${glyph.dot} `) || '—',
    connection.workerId ?? '—',
    String(connection.state ?? '—'),
    number(connection.weeklyUsedFraction) === null ? '—' : percent(connection.weeklyUsedFraction),
    number(connection.fableUsedFraction) === null ? '—' : percent(connection.fableUsedFraction),
    countdown(connection.resetsAt, nowMs),
  ]);
  return table(['provider', 'account', 'plan', 'worker', 'state', 'weekly', 'fable', 'reset'], rows, new Set([5, 6]));
}

// ── commands ────────────────────────────────────────────────────────────────
function keyRefusal(endpoint, source, status) {
  const host = hostOf(endpoint);
  const lines = status === null ? [`This is not a personal gateway key: ${KEY_SHAPE} (provider API keys, box leases and the gateway root do not work here).`]
    : [`${host} refused this key (HTTP ${status}).`,
      source === 'env' ? `  The exported AGENT_AUTH_TOKEN is not a key ${host} recognizes.` : `  ${host} does not recognize the key you pasted.`];
  lines.push(`  Mint a key for ${host} in its console (${endpoint}/admin) and paste that one.`);
  return lines.join('\n');
}
function validateMe(value) {
  if (!record(value) || typeof value.name !== 'string' || value.name === '' || !ROLES.has(value.role) || (value.email !== null && typeof value.email !== 'string')) {
    throw new CliError('the gateway answered /admin/api/cli/me with an unexpected shape');
  }
  return { name: value.name, role: value.role, email: value.email };
}
async function reachable(endpoint) {
  try {
    await request(endpoint, null, 'GET', '/healthz', undefined, 20_000);
    return null;
  } catch (error) {
    if (error instanceof HttpError) { warn(`${endpoint}/healthz answered HTTP ${error.status}; continuing, but this may not be a gateway endpoint`); return null; }
    return error.message;
  }
}
export async function login(flags) {
  let endpoint;
  if (flags.url !== undefined) {
    const result = normalizeEndpoint(flags.url);
    if (result.error !== undefined) throw usage(result.error);
    endpoint = result.value;
    const problem = await reachable(endpoint);
    if (problem !== null) throw new CliError(problem);
    done('Gateway', endpoint);
  } else {
    if (!interactive()) throw usage('pass --url when no terminal is available');
    for (;;) {
      endpoint = await ask('Gateway host or URL', normalizeEndpoint, 'Gateway');
      const problem = await reachable(endpoint);
      if (problem === null) break;
      term(`${tint('33', '!')} ${problem}\n`);
    }
  }
  let token = process.env.AGENT_AUTH_TOKEN ?? '';
  let source = token === '' ? 'entered' : 'env';
  if (token === '') {
    if (!interactive()) throw usage('set AGENT_AUTH_TOKEN or run from a terminal to enter the key');
    token = await secret('Gateway key', 'Key');
  }
  let identity;
  for (let attempts = 0; ; attempts++) {
    let refusal = null;
    if (!acceptKey(token)) refusal = keyRefusal(endpoint, source, null);
    else {
      try { identity = validateMe(await request(endpoint, token, 'GET', '/admin/api/cli/me')); break; } catch (error) {
        if (!(error instanceof HttpError) || ![401, 403].includes(error.status)) throw error;
        refusal = keyRefusal(endpoint, source, error.status);
      }
    }
    if (!interactive() || source === 'env' || attempts >= 2) throw new CliError(refusal);
    term(`${tint('33', '!')} ${refusal}\n`);
    if (await select('Key refused', [{ value: 'retry', label: 'Paste a different key' }, { value: 'quit', label: 'Quit without changing anything' }]) === 'quit') {
      throw new CliError('Left the login alone; nothing was stored.');
    }
    token = await secret('Gateway key', 'Key');
  }
  const session = { endpoint, token, ...identity };
  saveSession(session);
  done('Logged in', `${session.name} ${glyph.dot} ${session.role} ${glyph.dot} ${endpoint}`);
  return session;
}
function logout() {
  clearSession();
  done('Logged out', sessionFile());
}
function status(session, flags) {
  header(session);
  out('');
  out(renderStatus(statusRows(session, flags.profile)));
}
async function model(session, client, requested, flags) {
  checkProfile(client, flags.profile);
  const models = servedModels(await api(session, 'GET', '/v1/models'), client);
  let current = null;
  try { current = currentModelId(readState(resolveScope(client, flags.profile).stateFile, client.id)); } catch { current = null; }
  if (requested !== undefined) {
    if (!models.some(entry => entry.id === requested)) throw new CliError(`model ${requested} is not served for ${client.label}; served models: ${models.map(entry => entry.id).join(', ')}`);
    return configure(session, client, { ...flags, model: requested });
  }
  if (!interactive()) { out(renderModels(models, current)); return true; }
  const choice = await select('Model', models.map(entry => ({
    value: entry.id, label: entry.id,
    hint: [PROVIDER_LABELS[entry.provider] ?? entry.provider, entry.name !== entry.id ? entry.name : '', entry.id === current ? 'current' : ''].filter(Boolean).join(` ${glyph.dot} `),
  })), Math.max(0, models.findIndex(entry => entry.id === current)));
  return configure(session, client, { ...flags, model: choice });
}
async function showUsage(session) {
  const payload = await api(session, 'GET', '/admin/api/cli/usage');
  out(paint('1', `usage ${glyph.dot} ${session.name}`));
  out('');
  out(renderUsage(payload));
}
async function showCapacity(session) {
  out(renderCapacity(await api(session, 'GET', '/admin/api/cli/capacity')));
}
async function showConnections(session) {
  out(renderConnections(await api(session, 'GET', '/admin/api/cli/connections')));
}

// ── add connection ──────────────────────────────────────────────────────────
// A port of login-runtime/local-admin.mjs: the worker runs the OAuth exchange;
// this process only relays the browser's callback (Anthropic) or shows the
// device code (Codex) and polls until the link settles.
function validateLink(value) {
  if (!record(value) || typeof value.attemptId !== 'string' || !ATTEMPT_ID.test(value.attemptId)
    || typeof value.provider !== 'string' || typeof value.workerId !== 'string' || !LINK_STATUSES.has(value.status)
    || (value.url !== null && (typeof value.url !== 'string' || !value.url.startsWith('https://')))
    || (value.userCode !== null && typeof value.userCode !== 'string')
    || (value.error !== null && typeof value.error !== 'string')) {
    throw new CliError('the gateway returned an invalid OAuth link');
  }
  return { attemptId: value.attemptId, provider: value.provider, workerId: value.workerId, status: value.status, url: value.url, userCode: value.userCode, error: value.error };
}
const linkBody = (link, extra = {}) => ({ workerId: link.workerId, attemptId: link.attemptId, provider: link.provider, ...extra });
function openBrowser(url) {
  const command = process.platform === 'darwin' ? 'open' : 'xdg-open';
  try {
    const child = spawn(command, [url], { detached: true, stdio: 'ignore' });
    child.on('error', () => {});
    child.unref();
  } catch { /* the URL is printed; opening is best effort */ }
}
function callbackPage(ok) {
  const body = `<!doctype html><meta charset="utf-8"><title>genesis</title><body>${ok ? 'Authorization received. Return to the terminal.' : 'Connection failed. Return to the terminal.'}</body>`;
  return { status: ok ? 200 : 400, body };
}
function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolve(); });
  });
}
// Anthropic redirects the browser to http://localhost:<port>/callback; the
// worker's authorization URL names the port and a 32-hex state. The code is
// forwarded to link/input once; the servers close after that answer is sent.
// A request line the handler cannot parse gets the failure page; anything
// else that goes wrong in it reaches `fail`, never the server.
async function anthropicCallback(session, link, onLink, fail) {
  const authorize = new URL(link.url);
  const redirect = authorize.searchParams.get('redirect_uri');
  const expectedState = authorize.searchParams.get('state');
  if (redirect === null || expectedState === null || !/^[0-9a-f]{32}$/.test(expectedState)) throw new CliError('the worker returned an invalid Anthropic authorization URL');
  const callbackUrl = new URL(redirect);
  const port = Number(callbackUrl.port || 80);
  const servers = [];
  let consumed = false;
  const close = () => { for (const server of servers) { server.closeAllConnections?.(); server.close(); } servers.length = 0; };
  const handler = async (req, res) => {
    let callback = null;
    try { callback = new URL(req.url ?? '/', callbackUrl.origin); } catch { /* the failure page */ }
    const local = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
    let page = callbackPage(false);
    if (callback !== null && req.method === 'GET' && local && callback.pathname === '/callback' && callback.searchParams.get('state') === expectedState
      && callback.searchParams.get('code') !== null && !consumed) {
      consumed = true;
      try { onLink(validateLink(await api(session, 'POST', '/admin/api/cli/link/input', linkBody(link, { input: callback.toString() })))); page = callbackPage(true); }
      catch (error) { warn(error.message); }
    }
    res.writeHead(page.status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'close', 'Content-Length': Buffer.byteLength(page.body) });
    res.end(page.body, () => { if (consumed) close(); });
  };
  const serve = () => http.createServer((req, res) => { handler(req, res).catch(fail); });
  const ipv4 = serve();
  try { await listen(ipv4, '127.0.0.1', port); } catch (error) {
    ipv4.close();
    if (error?.code === 'EADDRINUSE' || error?.code === 'EACCES') throw new CliError(`port ${port} on 127.0.0.1 is ${error.code === 'EACCES' ? 'not permitted' : 'in use'}; the Anthropic callback needs it, so free it and try again`);
    throw error;
  }
  servers.push(ipv4);
  const ipv6 = serve();
  try { await listen(ipv6, '::1', port); servers.push(ipv6); } catch { ipv6.close(); }
  return close;
}
async function addConnection(session, flags) {
  const topology = await api(session, 'GET', '/admin/api/cli/workers');
  const placement = record(topology) && Array.isArray(topology.placement) ? topology.placement.filter(record) : [];
  if (placement.length === 0) throw new CliError('worker topology is unavailable; try again shortly');
  let provider = flags.provider;
  if (provider === undefined) {
    if (!interactive()) throw usage('pass --provider anthropic|openai-codex (and optionally --worker ID) when no terminal is available');
    provider = await select('Provider', placement.map(entry => ({
      value: entry.provider, label: PROVIDER_LABELS[entry.provider] ?? String(entry.provider),
      hint: entry.available === true ? `next: ${entry.workerId}` : 'no slot',
    })));
  }
  const slot = placement.find(entry => entry.provider === provider);
  if (slot === undefined) throw usage(`unknown provider ${provider}; use ${placement.map(entry => entry.provider).join(', ')}`);
  let workerId = flags.worker ?? null;
  if (workerId === null && interactive() && Array.isArray(slot.availableWorkerIds) && slot.availableWorkerIds.length > 0) {
    workerId = await select('Worker', [
      { value: '', label: slot.workerId ? `automatic ${glyph.dot} ${slot.workerId}` : 'automatic' },
      ...slot.availableWorkerIds.filter(id => typeof id === 'string').map(id => ({ value: id, label: id })),
    ]) || null;
  }
  // Ctrl-C from here on cancels the worker's attempt instead of abandoning it;
  // it and a callback failure also cut the poll wait short.
  const stop = new AbortController();
  let interrupted = false;
  let failure = null;
  const onInterrupt = () => { interrupted = true; stop.abort(); };
  const fail = error => { failure ??= error; stop.abort(); };
  process.on('SIGINT', onInterrupt);
  let link = null;
  let closeCallback = null;
  let shownUrl = null;
  let shownCode = null;
  // The authorization URL and the device code are each shown once, as soon as
  // the worker reports them. Anthropic's loopback callback is bound before the
  // URL is shown or opened, so a browser can never race an unbound port.
  const show = async () => {
    if (link.url !== null && shownUrl !== link.url) {
      shownUrl = link.url;
      if (link.provider === 'anthropic' && closeCallback === null && !LINK_TERMINAL.has(link.status)) {
        closeCallback = await anthropicCallback(session, link, next => { link = next; }, fail);
      }
      out(`open ${link.url}`);
      openBrowser(link.url);
    }
    if (link.userCode !== null && shownCode !== link.userCode) { shownCode = link.userCode; done('Code', link.userCode); }
  };
  // Whatever ends this command, a started link that has not settled is
  // cancelled on the worker once. Returns the cancel failure, if any, so an
  // interrupt reports it while another error keeps its own reason; once the
  // worker has taken the cancel, an interrupt exits 130 even when a stale
  // poll failed on the way.
  let asked = false;
  let cancelled = false;
  const cancel = async () => {
    if (asked || link === null || LINK_TERMINAL.has(link.status)) return null;
    asked = true;
    try { link = validateLink(await api(session, 'POST', '/admin/api/cli/link/cancel', linkBody(link))); cancelled = true; return null; } catch (error) { return error; }
  };
  // Checked after every wait and every request: a callback failure ends the
  // command with its error; an interrupt or the deadline ends it by cancelling.
  const deadline = Date.now() + LINK_LIMIT_MS;
  const settled = async () => {
    if (failure !== null) throw failure;
    if (!interrupted && Date.now() <= deadline) return false;
    const problem = await cancel();
    if (problem !== null) throw problem;
    return true;
  };
  try {
    const started = await api(session, 'POST', '/admin/api/cli/link/start', { provider, workerId }, 60_000);
    if (record(started) && record(started.provisioning) && started.workerId === null) {
      note(`${started.provisioning.state} ${glyph.dot} ${started.provisioning.workerId ?? 'worker'}; run this again when it is ready`);
      return;
    }
    link = validateLink(started);
    note(`${link.workerId} ${glyph.dot} ${link.status}`);
    await show();
    let last = link.status;
    while (!LINK_TERMINAL.has(link.status)) {
      if (await settled()) break;
      await sleep(LINK_POLL_MS, undefined, { signal: stop.signal }).catch(() => {});
      if (await settled() || LINK_TERMINAL.has(link.status)) break;
      const next = validateLink(await api(session, 'POST', '/admin/api/cli/link/status', linkBody(link)));
      if (next.attemptId === link.attemptId) link = next;
      if (link.status !== last) { last = link.status; note(`${link.workerId} ${glyph.dot} ${link.status}`); }
      await show();
    }
  } catch (error) {
    await cancel();
    if (interrupted && cancelled) throw new Interrupt();
    throw error;
  } finally {
    process.off('SIGINT', onInterrupt);
    if (closeCallback !== null) closeCallback();
  }
  if (link.status === 'done') { done('Connected', `${PROVIDER_LABELS[link.provider] ?? link.provider} on ${link.workerId}`); return; }
  if (interrupted) throw new Interrupt();
  throw new CliError(`connection ${link.status}${link.error ? `: ${link.error}` : ''}`);
}

// ── key rotation ────────────────────────────────────────────────────────────
// The server re-mints the key under the same name and revokes the old row.
// The new session is committed (on disk and, through `commit`, in memory)
// before any scope is touched. Every enumerable scope configured for this
// endpoint is then staged again with the new key and its saved model; a scope
// that was disabled is disabled again. configure and disable are judged
// apart, since a failed configure leaves the old key in place while a failed
// disable leaves the new key enabled; each such scope, each scope that could
// not be checked, and what is never enumerated (OMP profiles) is reported
// after, and any of the first two exits 1 with the new session kept.
async function rotateToken(session, flags, commit = () => {}) {
  if (!flags.yes) {
    if (!interactive()) throw usage('token rotate needs --yes without a terminal');
    if (!(await confirm(`Rotate the key for ${session.name}? The current key stops working everywhere`))) { out('Left the key alone.'); return; }
  }
  const rows = statusRows(session);
  const scopes = rows.filter(row => row.state !== null && row.state.gateway === session.endpoint);
  const minted = await api(session, 'POST', '/admin/api/cli/token/rotate', {});
  if (!record(minted) || !acceptKey(minted.token) || typeof minted.name !== 'string') {
    throw new CliError('the gateway answered token/rotate with an unexpected shape');
  }
  const next = { ...session, token: minted.token, name: minted.name };
  saveSession(next);
  commit(next);
  done('Rotated', `${next.name}; the previous key is revoked`);
  const stage = async (row, action, args, withToken) => {
    try { await runSetup(next, row.client, action, args, withToken); return true; } catch (error) {
      if (error instanceof Interrupt) throw error;
      if (error.message) warn(error.message);
      return false;
    }
  };
  const restaged = [];
  const stale = [];
  const enabled = [];
  for (const row of scopes) {
    note(`re-staging ${row.label}`);
    const profile = profileArgs(row.profile || undefined);
    const model = row.state.model ? ['--model', rawModelId(row.state.model)] : [];
    if (!(await stage(row, 'configure', ['--new-key', '--overwrite', ...model, ...profile], true))) { stale.push(row); continue; }
    if (row.state.mode === 'disabled' && !(await stage(row, 'disable', profile, false))) { enabled.push(row); continue; }
    restaged.push(row.state.mode === 'disabled' ? `${row.label} ${glyph.dot} disabled` : row.label);
  }
  done('Restaged', restaged.join(', ') || 'none');
  const command = (row, action) => `genesis ${action} ${row.client.id}${row.profile ? ` --profile ${row.profile}` : ''}`;
  for (const row of stale) warn(`${row.label} still holds the old key — run ${command(row, 'configure')}`);
  for (const row of enabled) warn(`${row.label} holds the new key but is enabled — run ${command(row, 'disable')}`);
  const unchecked = rows.filter(row => row.problem !== null);
  for (const row of unchecked) warn(`${row.label} was not checked: ${row.problem}`);
  note('OMP profiles other than default are not enumerated; run genesis configure omp --profile <name> for each');
  const problems = stale.length + enabled.length + unchecked.length;
  if (problems > 0) throw new CliError(`the new key is stored; ${problems} scope${problems === 1 ? '' : 's'} above need${problems === 1 ? 's' : ''} attention`);
}

// ── update ──────────────────────────────────────────────────────────────────
// The only code source is the publisher URL the install recorded in
// release.json; a gateway endpoint never supplies code. Redirects are followed
// by hand, at most five, and every hop must be a trusted location before it
// is requested. The script runs with the same stdin it would get from
// curl | bash, its output relayed through the redactor, and does not relaunch
// the dashboard.
const trustedUrl = url => typeof url === 'string' && (url.startsWith('https://') || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(\/|$)/.test(url));
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
async function fetchScript(url) {
  let current = url;
  for (let hops = 0; ; hops++) {
    let response;
    try { response = await fetch(current, { redirect: 'manual', signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) }); } catch (error) { throw new CliError(`could not download ${current}: ${reasonOf(error)}`); }
    if (!REDIRECTS.has(response.status)) {
      if (!response.ok) throw new CliError(`could not download ${current}: HTTP ${response.status}`);
      const text = await response.text();
      if (!text.startsWith('#!')) throw new CliError(`${current} did not return an installer script`);
      return text;
    }
    await response.body?.cancel();
    const location = response.headers.get('location');
    let next = null;
    if (location !== null) { try { next = new URL(location, current).href; } catch { /* refused below */ } }
    if (next === null || !trustedUrl(next)) throw new CliError(`${current} redirected to ${location ?? 'nowhere'}, which is not an https location`);
    if (hops === 5) throw new CliError(`${url} redirected more than 5 times`);
    current = next;
  }
}
async function update() {
  const release = releaseInfo();
  if (release === null) throw new CliError(`no release.json beside ${path.join(here, 'genesis.mjs')} (a source checkout is not updated in place); rerun the published install line`);
  if (!trustedUrl(release.installUrl)) throw new CliError(`${path.join(here, 'release.json')} records no https install URL; rerun the published install line`);
  const script = await fetchScript(release.installUrl);
  note(`installing from ${release.installUrl}`);
  const child = spawn('bash', ['-s'], { env: { ...process.env, GENESIS_NO_LAUNCH: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
  relay(child.stdout, process.stdout);
  relay(child.stderr, process.stderr);
  child.stdin.end(script);
  const [code] = await once(child, 'close');
  if (code !== 0) throw new CliError(`update exited ${code}`);
}

// ── dashboard ───────────────────────────────────────────────────────────────
const clientMenu = rows => rows.map(row => ({ value: row, label: row.label, hint: `${row.status}${row.state?.model ? ` ${glyph.dot} ${row.state.model}` : ''}` }));
async function clientActions(session) {
  const rows = statusRows(session);
  const row = await select('Client', clientMenu(rows));
  const flags = { profile: row.profile || undefined };
  const action = await select('Action', [
    { value: 'configure', label: 'Configure' },
    { value: 'model', label: 'Model' },
    { value: 'enable', label: 'Enable' },
    { value: 'disable', label: 'Disable' },
    { value: 'unset', label: 'Unset' },
    { value: 'back', label: 'Back' },
  ]);
  if (action === 'configure') await configure(session, row.client, flags);
  else if (action === 'model') await model(session, row.client, undefined, flags);
  else if (action !== 'back') await switchScope(session, row.client, action, flags);
}
async function refreshIdentity(session) {
  try {
    const identity = validateMe(await api(session, 'GET', '/admin/api/cli/me'));
    if (identity.name !== session.name || identity.role !== session.role || identity.email !== session.email) {
      const next = { ...session, ...identity };
      saveSession(next);
      return next;
    }
    return session;
  } catch (error) {
    if (error instanceof HttpError && error.status === 401) {
      warn(`${hostOf(session.endpoint)} no longer accepts the stored key; log in again`);
      return login({ url: session.endpoint });
    }
    warn(error.message);
    return session;
  }
}
async function dashboard() {
  if (!interactive()) throw usage('no terminal; run a command instead (genesis --help)');
  let session = loadSession();
  session = session === null ? await login({}) : await refreshIdentity(session);
  for (;;) {
    out('');
    header(session);
    out('');
    out(renderStatus(statusRows(session)));
    out('');
    const privileged = ['owner', 'admin'].includes(session.role);
    const owner = session.role === 'owner';
    const choice = await select('Menu', [
      { value: 'client', label: 'Configure a client' },
      { value: 'usage', label: 'Show usage' },
      ...(privileged ? [{ value: 'capacity', label: 'Capacity' }, { value: 'connections', label: 'Connections' }] : []),
      ...(owner ? [{ value: 'add', label: 'Add connection' }, { value: 'rotate', label: 'Rotate my key' }] : []),
      { value: 'update', label: 'Update' },
      { value: 'quit', label: 'Quit' },
    ]);
    if (choice === 'quit') return;
    try {
      if (choice === 'client') await clientActions(session);
      else if (choice === 'usage') await showUsage(session);
      else if (choice === 'capacity') await showCapacity(session);
      else if (choice === 'connections') await showConnections(session);
      else if (choice === 'add') await addConnection(session, {});
      else if (choice === 'rotate') await rotateToken(session, {}, next => { session = next; });
      else if (choice === 'update') { await update(); return; }
    } catch (error) {
      if (error instanceof Interrupt || !(error instanceof CliError)) throw error;
      if (error.message !== '') warn(error.message);
    }
  }
}

// ── arguments ───────────────────────────────────────────────────────────────
const HELP = `Usage: genesis [command] [options]

  genesis                                   dashboard
  login [--url URL]                         sign in (AGENT_AUTH_TOKEN or a hidden prompt)
  logout
  status [--profile P]
  configure <client> [--model ID] [--profile P] [--overwrite]
  enable | disable | unset <client> [--profile P]
  model <client> [ID] [--profile P]         list or pick the client's default model
  usage                                     your recorded usage
  capacity                                  owner/admin
  connections [list | add]                  owner/admin; add: owner [--provider P] [--worker ID]
  token rotate [--yes]                      owner
  update | --update
  --version | --help

Clients: ${CLIENTS.map(client => client.id).join(', ')}
Exit codes: 0 ok, 1 failure, 2 usage`;
const VALUE_FLAGS = new Set(['url', 'model', 'profile', 'provider', 'worker']);
const SWITCH_FLAGS = new Set(['overwrite', 'yes', 'version', 'help', 'update']);
export function parseArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === '-h') { flags.help = true; continue; }
    if (!argument.startsWith('--')) { positionals.push(argument); continue; }
    const equals = argument.indexOf('=');
    const name = argument.slice(2, equals === -1 ? undefined : equals);
    if (VALUE_FLAGS.has(name)) {
      const value = equals === -1 ? argv[++index] : argument.slice(equals + 1);
      if (value === undefined || value === '') throw usage(`--${name} needs a value`);
      flags[name] = value;
    } else if (SWITCH_FLAGS.has(name) && equals === -1) flags[name] = true;
    else throw usage(`unknown option ${argument}; see genesis --help`);
  }
  return { positionals, flags };
}
async function main(argv) {
  primeSecrets();
  const { positionals, flags } = parseArgs(argv);
  const [command, ...rest] = positionals;
  if (flags.help || command === 'help') { out(HELP); return; }
  if (flags.version) { out(`genesis ${releaseInfo()?.commit ?? 'source'}`); return; }
  if (flags.update || command === 'update') { await update(); return; }
  const expect = count => { if (rest.length !== count) throw usage(`${command} takes ${count === 0 ? 'no arguments' : `${count} argument${count === 1 ? '' : 's'}`}; see genesis --help`); };
  switch (command) {
    case undefined: await dashboard(); return;
    case 'login': expect(0); await login(flags); return;
    case 'logout': expect(0); logout(); return;
    case 'status': expect(0); status(requireSession(), flags); return;
    case 'configure': expect(1); await configure(requireSession(), clientById(rest[0]), flags); return;
    case 'enable': case 'disable': case 'unset': expect(1); await switchScope(requireSession(), clientById(rest[0]), command, flags); return;
    case 'model':
      if (rest.length < 1 || rest.length > 2) throw usage('model takes a client and an optional model id; see genesis --help');
      await model(requireSession(), clientById(rest[0]), rest[1], flags);
      return;
    case 'usage': expect(0); await showUsage(requireSession()); return;
    case 'capacity': expect(0); await showCapacity(requireSession()); return;
    case 'connections':
      if (rest.length === 0 || rest[0] === 'list') await showConnections(requireSession());
      else if (rest[0] === 'add' && rest.length === 1) await addConnection(requireSession(), flags);
      else throw usage('connections takes list or add; see genesis --help');
      return;
    case 'token':
      if (rest.length !== 1 || rest[0] !== 'rotate') throw usage('token takes rotate; see genesis --help');
      await rotateToken(requireSession(), flags);
      return;
    default: throw usage(`unknown command ${command}; see genesis --help`);
  }
}
function run() {
  main(process.argv.slice(2)).then(() => {
    closeTerminal();
    process.exitCode = 0;
  }, error => {
    closeTerminal();
    if (error instanceof CliError) {
      if (error.message !== '') process.stderr.write(redact(`${error.exitCode === 130 ? '' : 'genesis: '}${error.message}\n`));
      process.exitCode = error.exitCode;
      return;
    }
    process.stderr.write(redact(`genesis: ${error?.stack ?? error}\n`));
    process.exitCode = 1;
  });
}
function isEntry() {
  try { return process.argv[1] !== undefined && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url; } catch { return false; }
}
if (isEntry()) run();
