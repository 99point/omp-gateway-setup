#!/usr/bin/env node
// genesis: the client CLI for a Genesis gateway. One file, Node.js 18 or newer,
// no dependencies. It stores the endpoint and personal key the user logs in
// with, drives the reviewed agent-auth-setup.sh installer for every client
// change, and talks to the gateway's bearer-authenticated CLI door
// (/admin/api/cli/*). Nothing privileged lives here: the server decides what a
// key may do from its role.
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { emitKeypressEvents } from 'node:readline';
import ttyModule from 'node:tty';
import { fileURLToPath, pathToFileURL } from 'node:url';

// A personal key: the s99dev. prefix and 20-512 URL-safe characters. Anything
// else is refused before it can reach a request, and no key bytes are echoed.
const KEY = /^s99dev\.[A-Za-z0-9_-]{20,512}$/;
const KEY_SHAPE = 'those start with s99dev. followed by 20-512 letters, digits, _ or -';
const ROLES = new Set(['owner', 'admin', 'viewer', 'client']);
const HTTP_TIMEOUT_MS = 30_000;
const LINK_POLL_MS = 2_000;
const LOCAL_BODY_CAP = 16 * 1024;
const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LINK_STATUSES = new Set(['starting', 'awaiting-browser', 'exchanging', 'done', 'failed', 'cancelled']);
const LINK_TERMINAL = new Set(['done', 'failed', 'cancelled']);
const PROFILE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[\x21-\x7e]{1,256}$/;
const PROVIDER_LABELS = { anthropic: 'Anthropic', 'openai-codex': 'OpenAI' };
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
let screenOutput = null;
const colorOut = () => screenOutput === null && process.stdout.isTTY === true && ansi() && !process.env.NO_COLOR;
const paint = (code, text, enabled = colorOut()) => (enabled ? `\x1b[${code}m${text}\x1b[0m` : text);
const writeOutput = (target, text, encoding = 'utf8') => {
  const safe = redact(text);
  if (screenOutput !== null) screenOutput.push(encoding === 'latin1' ? Buffer.from(safe, 'latin1').toString('utf8') : safe);
  else target.write(safe, encoding);
};
const out = text => writeOutput(process.stdout, `${text}\n`);
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
    writeOutput(target, held.slice(0, cut), 'latin1');
    held = held.slice(cut);
  });
  source.on('close', () => { if (held !== '') writeOutput(target, held, 'latin1'); });
}

let terminal = null;
function tty() {
  if (terminal !== null) return terminal;
  let fd;
  try { fd = fs.openSync('/dev/tty', 'r+'); } catch { return null; }
  const input = new ttyModule.ReadStream(fd);
  emitKeypressEvents(input);
  const output = new ttyModule.WriteStream(fd);
  input.pause();
  terminal = { fd, input, output, cursorHidden: false, raw: false, alternateScreen: false };
  return terminal;
}
// Prompts need a terminal for output and /dev/tty for input; stdin may be a pipe.
export const interactive = () => process.stdout.isTTY === true && tty() !== null;
const colorTty = () => ansi() && !process.env.NO_COLOR;
const tint = (code, text) => paint(code, text, colorTty());
// Terminal text — prompts, echoes, menus and summaries — is always redacted.
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
  if (terminal.alternateScreen) fs.writeSync(terminal.fd, '\x1b[?1049l');
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
const BACK = Symbol('back');
const backOption = { value: BACK, label: 'Back' };
const clearScreen = () => term(ansi() ? '\x1b[H\x1b[2J' : '\f');
function renderScreen(view) {
  const width = Math.max(20, columns() - 1);
  const height = Math.max(8, tty().output.rows || 24);
  const options = view.options;
  view.selected = Math.max(0, Math.min(view.selected ?? 0, options.length - 1));
  const body = [view.body, view.notice].filter(Boolean).join('\n\n');
  const lines = redact(body).split('\n').flatMap(line => {
    const wrapped = [];
    for (let offset = 0; offset < line.length; offset += width) wrapped.push(line.slice(offset, offset + width));
    return wrapped.length === 0 ? [''] : wrapped;
  });
  const menuRows = Math.min(options.length, Math.max(1, height - 5));
  const bodyRows = Math.max(0, height - menuRows - 5);
  view.offset = Math.max(0, Math.min(view.offset ?? 0, Math.max(0, lines.length - bodyRows)));
  const firstOption = Math.max(0, Math.min(view.selected - menuRows + 1, options.length - menuRows));
  clearScreen();
  const title = redact(view.title);
  term(`${tint('1', title.length > width ? `…${title.slice(1 - width)}` : title)}\n\n`);
  if (bodyRows > 0 && body) {
    term(`${lines.slice(view.offset, view.offset + bodyRows).join('\n')}\n`);
    if (lines.length > bodyRows) term(`${tint('2', `${view.offset + 1}–${Math.min(lines.length, view.offset + bodyRows)}/${lines.length}`)}\n`);
  }
  term('\n');
  options.slice(firstOption, firstOption + menuRows).forEach((option, offset) => {
    const index = firstOption + offset;
    const prefix = `${index === view.selected ? glyph.pick : ' '} ${index + 1}  `;
    const label = `${prefix}${option.label}`;
    const hint = option.hint ? `  ${option.hint}` : '';
    const line = `${label}${hint}`;
    const clipped = line.length >= width ? `${line.slice(0, width - 2)}…` : line;
    term(`${index === view.selected ? tint('36', clipped) : clipped}\n`);
  });
}
// One screen owns terminal input until it is left. The route keeps its cursor
// and scroll position; Escape never confirms a highlighted action.
async function selectScreen(view, signal) {
  const { input, output } = tty();
  if (signal?.aborted) return BACK;
  let keypress, resize, abort, ended;
  try {
    return await new Promise((resolve, reject) => {
      keypress = (text, key) => {
        if (key?.ctrl && key.name === 'c') { reject(new Interrupt()); return; }
        if (key?.name === 'escape' || key?.name === 'left' || (key?.ctrl && key.name === 'd')) { resolve(BACK); return; }
        if (key?.name === 'return' || key?.name === 'enter') { resolve(view.options[view.selected ?? 0].value); return; }
        const count = view.options.length;
        if (key?.name === 'up' || text === 'k' || text === 'K') view.selected = ((view.selected ?? 0) + count - 1) % count;
        else if (key?.name === 'down' || text === 'j' || text === 'J') view.selected = ((view.selected ?? 0) + 1) % count;
        else if (key?.name === 'home') view.selected = 0;
        else if (key?.name === 'end') view.selected = count - 1;
        else if (key?.name === 'pageup') view.offset = Math.max(0, (view.offset ?? 0) - 5);
        else if (key?.name === 'pagedown') view.offset = (view.offset ?? 0) + 5;
        else if (/^[1-9]$/.test(text ?? '') && Number(text) <= count) view.selected = Number(text) - 1;
        else return;
        renderScreen(view);
      };
      resize = () => renderScreen(view);
      abort = () => resolve(BACK);
      ended = () => resolve(BACK);
      input.on('keypress', keypress);
      input.once('end', ended);
      output.on('resize', resize);
      signal?.addEventListener('abort', abort, { once: true });
      input.setRawMode(true);
      terminal.raw = true;
      input.resume();
      if (ansi()) { term('\x1b[?25l'); terminal.cursorHidden = true; }
      renderScreen(view);
    });
  } finally {
    input.off('keypress', keypress);
    input.off('end', ended);
    output.off('resize', resize);
    signal?.removeEventListener('abort', abort);
    restoreTerminal();
  }
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
const modelOptions = (models, current) => models.map(entry => ({
  value: entry.id, label: entry.id,
  hint: [PROVIDER_LABELS[entry.provider] ?? entry.provider, entry.name !== entry.id ? entry.name : '', entry.id === current ? 'current' : ''].filter(Boolean).join(` ${glyph.dot} `),
}));
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
    const { tokens } = window;
    // null counters mean the gateway's recorder checkpoint is unreadable, not
    // an idle account; null detail means no folded call measured it (write
    // TTLs are Anthropic-only, reasoning counts Codex-only).
    const count = value => (number(value) === null ? '—' : integer(value));
    const prompt = [tokens.input, tokens.cacheRead, tokens.cacheWrite].some(value => number(value) === null)
      ? null : tokens.input + tokens.cacheRead + tokens.cacheWrite;
    const ttl = record(tokens.cacheWriteTtl) ? tokens.cacheWriteTtl : null;
    return [key, ...types.map(type => bars(window.bars[type.id])), count(window.calls),
      count(prompt), count(tokens.input), count(tokens.cacheRead), count(tokens.cacheWrite),
      ttl === null ? '—' : `${count(ttl.ephemeral5m)}/${count(ttl.ephemeral1h)}`,
      count(tokens.output), count(tokens.reasoningTokens),
      number(window.cost) === null ? '—' : `$${window.cost.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`];
  });
  const head = ['window', ...types.map(type => `${type.label} bars`), 'calls',
    'prompt', 'uncached', 'cache read', 'cache write', '5m/1h', 'output', 'reasoning', 'cost'];
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
  const rendered = table(['provider', 'metric', 'bars', 'next bar', 'eligible', 'reset'], rows, new Set([2, 3]));
  // A view the server is serving from its last good read (a fresh read
  // failed) is stamped with that read's time, so old numbers never pass as new.
  if (payload.stale === true) {
    const at = number(payload.generatedAt) === null ? null : new Date(payload.generatedAt).toISOString().slice(0, 16).replace('T', ' ');
    return `${rendered}\nstale${at === null ? '' : ` ${glyph.dot} as of ${at}Z`}`;
  }
  return rendered;
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
    if (await selectScreen({ title: 'Key refused', options: [{ value: 'retry', label: 'Paste a different key' }, backOption] }) !== 'retry') {
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
  const choice = await selectScreen({
    title: `${client.label} ${glyph.step} Model`,
    selected: Math.max(0, models.findIndex(entry => entry.id === current)),
    options: [...modelOptions(models, current), backOption],
  });
  if (choice === BACK) return false;
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
// this process serves one page on 127.0.0.1 that picks the provider and
// worker, starts the link, shows the authorization URL or device code and
// reflects the link as it settles; it relays the browser's callback
// (Anthropic) and reports every settled link in the terminal. It never opens
// a browser: the user opens the printed URL in one of their choice, and
// nothing starts without a click on the page.
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
// Every local response is uncacheable and sized; JSON passes through redact()
// like the terminal does, since a gateway error may quote the key.
function send(res, status, type, body, sent) {
  res.writeHead(status, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body, sent);
}
const sendJson = (res, status, value) => send(res, status, 'application/json', redact(JSON.stringify(value)));
// A request body of at most LOCAL_BODY_CAP bytes; a larger one is cut off.
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > LOCAL_BODY_CAP) { reject(new CliError('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
// JSON for the page's script: a < never ends the script element.
const inline = value => JSON.stringify(value).replace(/</g, '\\u003c');
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
// else that goes wrong in it is reported, never thrown at the server.
async function anthropicCallback(session, link, onLink, onError) {
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
      catch (error) { onError(error.message); }
    }
    res.setHeader('Connection', 'close');
    send(res, page.status, 'text/html', page.body, () => { if (consumed) close(); });
  };
  const serve = () => http.createServer((req, res) => { handler(req, res).catch(error => onError(error.message)); });
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
// The page: the signed-in identity, the current connections, the provider and
// worker picks, one link at a time with its Open provider link or device code
// (copied with one click), and the state poll every LINK_POLL_MS. Every
// /api/* request carries the per-process nonce in X-S99-Local.
function launcherPage(session, nonce, preset) {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>genesis</title>
<style>
  :root { color-scheme: dark; }
  body { background:#101014; color:#d6d6dc; font:14px/1.6 ui-monospace,monospace; margin:2rem auto; max-width:64rem; padding:0 1rem; }
  button,select { background:#17171d; color:#d6d6dc; border:1px solid #33465e; padding:.35rem .6rem; font:inherit; }
  a { color:#9ecfff; } .muted { color:#7a7a85; } .bad { color:#f0917f; }
  ul { list-style:none; padding:0; } li { border-top:1px solid #24242d; padding:.4rem 0; }
  #authCodeRow { margin:.5rem 0; }
  #authCode { cursor:pointer; user-select:all; overflow-wrap:anywhere; }
</style>
<div id="session" class="muted"></div>
<ul id="connections"></ul>
<select id="provider" aria-label="Provider"></select>
<select id="worker" aria-label="Worker"><option value="">automatic</option></select>
<button id="add" disabled>Add</button> <button id="cancel" disabled>Cancel</button>
<div id="destination"></div>
<div id="link"></div>
<div id="authCodeRow" hidden>
  <button id="authCode" type="button" title="Copy code" aria-label="Copy auth code"></button>
  <button id="copyCode" type="button">Copy</button>
  <span id="copyStatus" role="status"></span>
</div>
<div id="error" class="bad" role="alert"></div>
<script>
const localNonce = ${inline(nonce)};
const labels = ${inline(PROVIDER_LABELS)};
let preset = ${inline(preset)};
document.title = 'genesis · ' + ${inline(hostOf(session.endpoint))};
document.querySelector('#session').textContent = ${inline(`${session.endpoint} · ${session.name} · ${session.role}`)};
const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char]));
async function api(path, body) {
  const init = body === undefined ? { headers: { 'X-S99-Local': localNonce } }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-S99-Local': localNonce }, body: JSON.stringify(body) };
  const response = await fetch(path, init);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || response.status);
  return result;
}
let placement = [];
let provisioning = null;
let link = null;
let wantedWorker = null;
let refreshFailed = false;
const busy = () => link !== null && !['done', 'failed', 'cancelled'].includes(link.status);
function paintLink() {
  const target = $('#link');
  if (link === null) target.textContent = '';
  else {
    const open = link.url && busy() ? ' · <a href="' + esc(link.url) + '" target="_blank" rel="noopener">Open ' + esc(labels[link.provider] || link.provider) + '</a>' : '';
    const error = link.error ? ' · <span class="bad">' + esc(link.error) + '</span>' : '';
    target.innerHTML = esc(labels[link.provider] || link.provider) + ' · ' + esc(link.workerId) + ' · ' + esc(link.status) + open + error;
  }
  const code = busy() && link.userCode ? link.userCode : '';
  const codeButton = $('#authCode');
  $('#authCodeRow').hidden = !code;
  if (codeButton.textContent !== code) { codeButton.textContent = code; $('#copyStatus').textContent = ''; }
  $('#cancel').disabled = !busy();
}
async function copyAuthCode() {
  const code = link?.userCode;
  const attemptId = link?.attemptId;
  if (!code) return;
  let message = 'Copied';
  try { await navigator.clipboard.writeText(code); } catch { message = 'Copy failed'; }
  if (link?.attemptId === attemptId && link?.userCode === code) $('#copyStatus').textContent = message;
}
$('#copyCode').onclick = copyAuthCode;
$('#authCode').onclick = copyAuthCode;
function paintDestination() {
  const next = placement.find(entry => entry.provider === $('#provider').value);
  const destination = $('#destination');
  const workerSelect = $('#worker');
  const wanted = wantedWorker ?? workerSelect.value;
  wantedWorker = null;
  const offered = Array.isArray(next?.availableWorkerIds) ? next.availableWorkerIds.filter(workerId => typeof workerId === 'string') : [];
  const selected = offered.includes(wanted) ? wanted : '';
  workerSelect.innerHTML = '<option value="">' + esc(next?.workerId ? 'automatic · ' + next.workerId : 'automatic') + '</option>'
    + offered.map(workerId => '<option value="' + esc(workerId) + '">' + esc(workerId) + '</option>').join('');
  workerSelect.value = selected;
  workerSelect.disabled = !next?.available || busy();
  if (next === undefined || next.unavailable) { destination.className = 'bad'; destination.textContent = 'topology unavailable'; }
  else if (next.available) { destination.className = ''; destination.textContent = 'next: ' + (selected || next.workerId); }
  else if (['provisioning', 'admitting'].includes(provisioning?.state)) { destination.className = ''; destination.textContent = provisioning.state + ' · ' + provisioning.workerId; }
  else { destination.className = 'bad'; destination.textContent = provisioning?.error || 'no slot'; }
  $('#add').textContent = 'Add' + ($('#provider').value ? ' ' + (labels[$('#provider').value] || $('#provider').value) : '');
  $('#add').disabled = !next?.available || busy();
  paintLink();
}
function paintError(error) {
  paintDestination();
  $('#error').textContent = String(error.message || error);
}
const clearError = () => { $('#error').textContent = ''; };
async function refresh() {
  try {
    const state = await api('/api/state');
    const selector = $('#provider');
    const selectedProvider = selector.value;
    placement = Array.isArray(state.workers?.placement) ? state.workers.placement.filter(entry => typeof entry?.provider === 'string') : [];
    provisioning = state.workers?.provision ?? null;
    const options = placement.map(entry => '<option value="' + esc(entry.provider) + '">' + esc(labels[entry.provider] || entry.provider) + '</option>').join('');
    if (selector.innerHTML !== options) { selector.innerHTML = options; if (placement.some(entry => entry.provider === selectedProvider)) selector.value = selectedProvider; }
    if (preset !== null) {
      if (placement.some(entry => entry.provider === preset.provider)) selector.value = preset.provider;
      wantedWorker = preset.workerId;
      preset = null;
    }
    link = state.link;
    const rows = Array.isArray(state.connections?.connections) ? state.connections.connections.filter(row => row !== null && typeof row === 'object') : [];
    $('#connections').innerHTML = rows.map(row => '<li><b>' + esc(labels[row.provider] || row.provider) + '</b> ' + esc(row.email || row.id)
      + ' <span class="muted">· ' + esc(row.workerId) + ' · ' + esc(row.state) + '</span></li>').join('');
    paintDestination();
    if (refreshFailed) { refreshFailed = false; clearError(); }
  } catch (error) {
    refreshFailed = true;
    paintError(error);
  }
  setTimeout(refresh, ${LINK_POLL_MS});
}
$('#provider').onchange = paintDestination;
$('#add').onclick = () => {
  clearError();
  $('#add').disabled = true;
  api('/api/link/start', { provider: $('#provider').value, workerId: $('#worker').value || null }).then(result => {
    link = result.link;
    if (result.provisioning) {
      provisioning = result.provisioning;
      placement = placement.map(entry => ({ ...entry, available: false, workerId: null, availableWorkerIds: [] }));
    }
    paintDestination();
  }).catch(paintError);
};
$('#cancel').onclick = () => {
  clearError();
  $('#cancel').disabled = true;
  api('/api/link/cancel', {}).then(result => { link = result.link; paintDestination(); }).catch(paintError);
};
refresh();
</script>`;
}
async function addConnection(session, flags, view = null) {
  let port = 0;
  if (flags.port !== undefined) {
    port = /^[0-9]{1,5}$/.test(flags.port) ? Number(flags.port) : 0;
    if (port < 1 || port > 65_535) throw usage('--port takes a number from 1 to 65535; the page is only ever served on 127.0.0.1');
  }
  const topology = await api(session, 'GET', '/admin/api/cli/workers');
  const placement = record(topology) && Array.isArray(topology.placement) ? topology.placement.filter(record) : [];
  if (placement.length === 0) throw new CliError('worker topology is unavailable; try again shortly');
  // --provider and --worker only preselect on the page; each must name what the topology offers.
  const slots = flags.provider === undefined ? placement : placement.filter(entry => entry.provider === flags.provider);
  if (slots.length === 0) throw usage(`unknown provider ${flags.provider}; use ${placement.map(entry => entry.provider).join(', ')}`);
  const workers = [...new Set(slots.flatMap(entry => [entry.workerId, ...(Array.isArray(entry.availableWorkerIds) ? entry.availableWorkerIds : [])]).filter(id => typeof id === 'string'))];
  if (flags.worker !== undefined && !workers.includes(flags.worker)) throw usage(`unknown worker ${flags.worker}${workers.length === 0 ? '' : `; use ${workers.join(', ')}`}`);
  const nonce = crypto.randomBytes(32).toString('base64url');
  const nonceMatches = value => {
    if (typeof value !== 'string') return false;
    const supplied = Buffer.from(value);
    const expected = Buffer.from(nonce);
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  };
  const page = launcherPage(session, nonce, { provider: flags.provider ?? null, workerId: flags.worker ?? null });
  let link = null;
  let closeCallback = null;
  let starting = null;
  let cancelling = null;
  let closing = false;
  let localUrl = '';
  let cancellationError = null;
  const report = (text, failed = false) => {
    if (view === null) { (failed ? warn : note)(text); return; }
    if (closing) return;
    view.body = `${localUrl}\n\n${text}`;
    renderScreen(view);
  };
  const busy = () => link !== null && !LINK_TERMINAL.has(link.status);
  // Every link answer lands here. A status change is reported in the
  // terminal (a settled link as Connected or a failure, otherwise the new
  // state) and a settled link releases Anthropic's callback port.
  const settle = next => {
    const changed = link === null || next.attemptId !== link.attemptId || next.status !== link.status;
    link = next;
    if (changed && link.status === 'done') {
      const connected = `${PROVIDER_LABELS[link.provider] ?? link.provider} on ${link.workerId}`;
      if (view === null) done('Connected', connected);
      else report(`Connected ${glyph.dot} ${connected}`);
    } else if (changed && link.status === 'failed') report(`connection failed${link.error ? `: ${link.error}` : ''}`, true);
    else if (changed) report(`${PROVIDER_LABELS[link.provider] ?? link.provider} ${glyph.dot} ${link.workerId} ${glyph.dot} ${link.status}`);
    if (LINK_TERMINAL.has(link.status) && closeCallback !== null) { closeCallback(); closeCallback = null; }
  };
  // Late polls and callbacks must not revive a cancelled or replaced attempt.
  const adopt = next => { if (!closing && link !== null && !LINK_TERMINAL.has(link.status) && next.attemptId === link.attemptId) settle(next); };
  // A link that has not settled is cancelled on the worker once. When that
  // fails it is marked cancelled here, since the worker's copy is taken over
  // by the next start on it (or ends with its own timeout) and the page must
  // not stay wedged behind it.
  const cancel = async () => {
    if (!busy()) return link;
    cancelling ??= (async () => {
      try { settle(validateLink(await api(session, 'POST', '/admin/api/cli/link/cancel', linkBody(link)))); }
      catch (error) { cancellationError = error.message; report(error.message, true); settle({ ...link, status: 'cancelled', error: error.message }); }
      finally { cancelling = null; }
    })();
    await cancelling;
    return link;
  };
  // Anthropic's callback port is bound before the URL leaves this process,
  // so a browser can never race an unbound port; when it cannot be bound the
  // link is cancelled and kept without its URL.
  const bindCallback = async () => {
    if (closing || !busy() || link.provider !== 'anthropic' || link.url === null || closeCallback !== null) return;
    try { closeCallback = await anthropicCallback(session, link, adopt, text => report(text, true)); }
    catch (error) { await cancel(); settle({ ...link, url: null, error: error.message }); throw error; }
  };
  const refresh = async () => {
    if (closing || !busy()) return;
    const current = link;
    const next = validateLink(await api(session, 'POST', '/admin/api/cli/link/status', linkBody(current)));
    if (link !== current) return;
    adopt(next);
    await bindCallback();
  };
  const start = async (provider, workerId) => {
    if (closing) throw new CliError('shutting down');
    if (starting !== null || busy()) throw new CliError('a connection is already being added');
    cancellationError = null;
    starting = (async () => {
      const started = await api(session, 'POST', '/admin/api/cli/link/start', { provider, workerId }, 60_000);
      if (record(started) && record(started.provisioning) && started.workerId === null) {
        report(`${started.provisioning.state} ${glyph.dot} ${started.provisioning.workerId ?? 'worker'}`);
        return { link, provisioning: started.provisioning };
      }
      settle(validateLink(started));
      await bindCallback();
      return { link };
    })();
    try { return await starting; } finally { starting = null; }
  };
  const server = http.createServer();
  try { await listen(server, '127.0.0.1', port); } catch (error) {
    server.close();
    if (error?.code === 'EADDRINUSE' || error?.code === 'EACCES') throw new CliError(`port ${port} on 127.0.0.1 is ${error.code === 'EACCES' ? 'not permitted' : 'in use'}; pass another --port`);
    throw error;
  }
  const local = `127.0.0.1:${server.address().port}`;
  // The Host must be this bind and, on /api/*, the nonce must match and any
  // Origin must be this page's: a page from anywhere else, or a rebound name,
  // gets 403 and nothing about the link.
  const serve = async (req, res) => {
    if (req.headers.host !== local) { sendJson(res, 403, { error: 'invalid local host' }); return; }
    // Judged on the parsed path: an absolute-form request target would
    // otherwise slip past a prefix test on the raw line.
    let url;
    try { url = new URL(req.url ?? '/', `http://${local}`); } catch { sendJson(res, 400, { error: 'invalid request target' }); return; }
    if (url.origin !== `http://${local}`) { sendJson(res, 403, { error: 'invalid local host' }); return; }
    if (url.pathname.startsWith('/api/') && (!nonceMatches(req.headers['x-s99-local']) || (req.headers.origin !== undefined && req.headers.origin !== `http://${local}`))) {
      sendJson(res, 403, { error: 'local request authentication required' });
      return;
    }
    if (closing) { res.setHeader('Connection', 'close'); sendJson(res, 503, { error: 'shutting down' }); return; }
    if (req.method === 'GET' && url.pathname === '/') { send(res, 200, 'text/html', page); return; }
    if (req.method === 'GET' && url.pathname === '/api/state') {
      const [workers, connections] = await Promise.all([api(session, 'GET', '/admin/api/cli/workers'), api(session, 'GET', '/admin/api/cli/connections'), refresh()]);
      sendJson(res, 200, { workers, connections, link });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/link/start') {
      const body = JSON.parse(await readBody(req));
      if (!record(body) || typeof body.provider !== 'string' || (body.workerId !== null && typeof body.workerId !== 'string')) throw new CliError('invalid link request');
      const result = await start(body.provider, body.workerId);
      sendJson(res, result.provisioning ? 202 : 200, result);
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/link/cancel') { await readBody(req); sendJson(res, 200, { link: await cancel() }); return; }
    sendJson(res, 404, { error: 'not found' });
  };
  server.on('request', (req, res) => { serve(req, res).catch(error => sendJson(res, error instanceof HttpError ? error.status : 400, { error: String(error?.message ?? error) })); });
  localUrl = `open http://${local}/`;
  const navigation = new AbortController();
  let finish;
  let shutdownTask = null;
  let interrupted = false;
  const finished = new Promise(resolve => { finish = resolve; });
  // Back and signals share one cleanup. A start already in flight is joined
  // before cancelling, so leaving cannot orphan its newly returned attempt.
  const shutdown = () => {
    if (shutdownTask !== null) return shutdownTask;
    closing = true;
    server.close();
    server.closeIdleConnections?.();
    if (closeCallback !== null) { closeCallback(); closeCallback = null; }
    shutdownTask = (async () => {
      await starting?.catch(() => {});
      await cancel();
      if (closeCallback !== null) { closeCallback(); closeCallback = null; }
      server.closeAllConnections?.();
      finish();
      return cancellationError;
    })();
    return shutdownTask;
  };
  const interrupt = () => {
    if (interrupted) { closeTerminal(); process.exit(130); }
    interrupted = true;
    navigation.abort();
    void shutdown();
  };
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', interrupt);
  try {
    if (view === null) { out(localUrl); await finished; }
    else {
      view.body = localUrl;
      view.options = [backOption];
      try { await selectScreen(view, navigation.signal); }
      catch (error) { if (error instanceof Interrupt) interrupted = true; else throw error; }
    }
  } finally {
    const cleanup = shutdown();
    if (view === null || interrupted) await cleanup;
    process.off('SIGINT', interrupt);
    process.off('SIGTERM', interrupt);
  }
  if (interrupted) throw new Interrupt();
  return { cleanup: shutdownTask };
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
  const stack = [{ route: 'dashboard', title: 'genesis', selected: 0 }];
  const pendingClosures = new Set();
  const navigation = new AbortController();
  let activeView = null;
  const interrupt = () => {
    if (navigation.signal.aborted) { closeTerminal(); process.exit(130); }
    navigation.abort();
  };
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', interrupt);
  const push = (route, label, fields = {}) => stack.push({
    route, title: `${stack.at(-1).title} ${glyph.step} ${label}`, selected: 0, ...fields,
  });
  const pop = () => {
    stack.pop();
    const parent = stack.at(-1);
    if (parent !== undefined) parent.ready = false;
  };
  const actions = [
    { value: 'configure', label: 'Configure' }, { value: 'model', label: 'Model' },
    { value: 'enable', label: 'Enable' }, { value: 'disable', label: 'Disable' }, { value: 'unset', label: 'Unset' },
  ];
  if (ansi()) { terminal.alternateScreen = true; term('\x1b[?1049h'); }
  try {
    while (stack.length > 0) {
      const view = stack.at(-1);
      if (navigation.signal.aborted) throw new Interrupt();
      try {
        if (view.route === 'add') {
          const { cleanup } = await addConnection(session, {}, view);
          const parent = stack.at(-2);
          const closing = cleanup.then(error => {
            if (error !== null) {
              parent.notice = error;
              if (activeView === parent) renderScreen(parent);
            }
          }).finally(() => pendingClosures.delete(closing));
          pendingClosures.add(closing);
          pop();
          continue;
        }
        if (!view.ready) {
          if (view.route === 'dashboard') {
            view.body = `${session.endpoint} ${glyph.dot} ${session.name} ${glyph.dot} ${session.role}\n\n${renderStatus(statusRows(session))}`;
            view.options = [
              { value: 'clients', label: 'Clients' }, { value: 'usage', label: 'Usage' },
              ...(['owner', 'admin'].includes(session.role) ? [{ value: 'capacity', label: 'Capacity' }, { value: 'connections', label: 'Connections' }] : []),
              ...(session.role === 'owner' ? [{ value: 'rotate', label: 'Rotate my key' }] : []),
              { value: 'update', label: 'Update' }, { value: BACK, label: 'Quit' },
            ];
          } else if (view.route === 'clients') {
            view.options = [...statusRows(session).map(row => ({
              value: row, label: row.label,
              hint: `${row.status}${row.state?.model ? ` ${glyph.dot} ${row.state.model}` : ''}`,
            })), backOption];
          } else if (view.route === 'actions') {
            view.options = [...actions, backOption];
            const row = statusRows(session, view.row.profile || undefined).find(entry => entry.client.id === view.row.client.id && entry.profile === view.row.profile);
            if (row !== undefined) view.row = row;
            view.body = renderStatus([view.row]);
          } else if (view.route === 'model') {
            const models = servedModels(await api(session, 'GET', '/v1/models'), view.row.client);
            const current = currentModelId(readState(resolveScope(view.row.client, view.row.profile || undefined).stateFile, view.row.client.id));
            if (view.options === undefined) view.selected = Math.max(0, models.findIndex(entry => entry.id === current));
            view.options = [...modelOptions(models, current), backOption];
          } else if (view.route === 'usage') {
            view.body = renderUsage(await api(session, 'GET', '/admin/api/cli/usage'));
            view.options = [backOption];
          } else if (view.route === 'capacity') {
            view.body = renderCapacity(await api(session, 'GET', '/admin/api/cli/capacity'));
            view.options = [backOption];
          } else if (view.route === 'connections') {
            view.body = renderConnections(await api(session, 'GET', '/admin/api/cli/connections'));
            view.options = [...(session.role === 'owner' ? [{ value: 'add', label: 'Add connection' }] : []), backOption];
          } else if (view.route === 'confirm') {
            view.options = [{ value: 'apply', label: view.actionLabel }, backOption];
          }
          view.ready = true;
        }
        activeView = view;
        let choice;
        try { choice = await selectScreen(view, navigation.signal); } finally { activeView = null; }
        if (navigation.signal.aborted) throw new Interrupt();
        if (choice === BACK) { pop(); continue; }
        if (view.route === 'dashboard') {
          const label = view.options.find(option => option.value === choice).label;
          if (choice === 'rotate' || choice === 'update') push('confirm', label, { action: choice, actionLabel: label, selected: 1 });
          else push(choice, label);
        } else if (view.route === 'clients') {
          push('actions', choice.label, { row: choice });
        } else if (view.route === 'actions') {
          const label = actions.find(action => action.value === choice).label;
          if (choice === 'model') push('model', label, { row: view.row });
          else push('confirm', label, { row: view.row, action: choice, actionLabel: label, selected: 1 });
        } else if (view.route === 'model') {
          push('confirm', choice, { row: view.row, action: 'configure', actionLabel: 'Configure', model: choice, selected: 1 });
        } else if (view.route === 'connections') {
          push('add', 'Add connection');
        } else if (view.route === 'confirm') {
          const output = [];
          screenOutput = output;
          renderScreen({ title: view.title, body: '', options: [] });
          try {
            if (view.action === 'rotate') await Promise.all(pendingClosures);
            const flags = { profile: view.row?.profile || undefined, model: view.model, overwrite: true };
            if (view.action === 'configure') await configure(session, view.row.client, flags);
            else if (['enable', 'disable', 'unset'].includes(view.action)) await switchScope(session, view.row.client, view.action, flags);
            else if (view.action === 'rotate') await rotateToken(session, { yes: true }, next => { session = next; });
            else if (view.action === 'update') await update();
          } catch (error) {
            if (error instanceof Interrupt || !(error instanceof CliError)) throw error;
            if (error.message !== '') warn(error.message);
          } finally {
            screenOutput = null;
            view.body = output.join('').trim();
            view.options = [backOption];
            view.selected = 0;
            view.route = 'result';
          }
        }
      } catch (error) {
        if (error instanceof Interrupt || !(error instanceof CliError)) throw error;
        view.route = 'result';
        view.body = error.message;
        view.options = [backOption];
        view.selected = 0;
        view.ready = true;
      }
    }
  } finally {
    activeView = null;
    await Promise.all(pendingClosures);
    process.off('SIGINT', interrupt);
    process.off('SIGTERM', interrupt);
    closeTerminal();
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
  connections [list | add]                  owner/admin; add: owner, serves a local page [--provider P] [--worker ID] [--port N]
  token rotate [--yes]                      owner
  update | --update
  --version | --help

Clients: ${CLIENTS.map(client => client.id).join(', ')}
Exit codes: 0 ok, 1 failure, 2 usage`;
const VALUE_FLAGS = new Set(['url', 'model', 'profile', 'provider', 'worker', 'port']);
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
