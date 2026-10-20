// Headless regression test for the add-workspace flow's client half.
//
// The browser bundle talks to React and to the Host over fetch; this script
// stands in for both (a minimal hook runtime plus a scripted fetch) and drives
// the REAL src/client.js, so "取消" behaviour is verified without a GUI:
//   - a dismissal reports exactly one outcome,
//   - a dismissal mid-flight never adopts a directory, creates a workspace, or
//     switches the default target (the "取消 did not really cancel" bug),
//   - a normal 打开 still does all three,
//   - backdrop clicks and Escape dismiss,
//   - a fresh open edge after a dismissal works again.
//
// Run with: node scripts/test-client-flow.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = process.env.CLIENT_SRC || join(root, 'src', 'client.js');

// ── minimal React runtime ───────────────────────────────────────────────────
const Fragment = Symbol('Fragment');
let hookList = [];
let hookIndex = 0;
let dirty = false;

function useState(initial) {
  const index = hookIndex++;
  if (!(index in hookList)) hookList[index] = { kind: 'state', value: typeof initial === 'function' ? initial() : initial };
  const slot = hookList[index];
  const set = (next) => {
    const value = typeof next === 'function' ? next(slot.value) : next;
    if (Object.is(value, slot.value)) return;
    slot.value = value;
    dirty = true;
  };
  return [slot.value, set];
}

function useRef(initial) {
  const index = hookIndex++;
  if (!(index in hookList)) hookList[index] = { kind: 'ref', ref: { current: initial } };
  return hookList[index].ref;
}

function depsEqual(a, b) {
  return Boolean(a && b) && a.length === b.length && a.every((value, index) => Object.is(value, b[index]));
}

function useCallback(fn, deps) {
  const index = hookIndex++;
  const slot = hookList[index];
  if (!slot || slot.kind !== 'callback' || !depsEqual(slot.deps, deps)) hookList[index] = { kind: 'callback', deps, fn };
  return hookList[index].fn;
}

function useEffect(fn, deps) {
  const index = hookIndex++;
  const slot = hookList[index];
  if (!slot || slot.kind !== 'effect' || !depsEqual(slot.deps, deps)) {
    hookList[index] = { kind: 'effect', deps, fn, dirty: true, cleanup: slot && slot.cleanup };
  }
}

const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children }),
  Fragment,
  useState,
  useRef,
  useEffect,
  useCallback,
};

// ── browser environment mocks ───────────────────────────────────────────────
const storage = new Map();
globalThis.localStorage = {
  getItem: (key) => (storage.has(key) ? storage.get(key) : null),
  setItem: (key, value) => { storage.set(key, String(value)); },
  removeItem: (key) => { storage.delete(key); },
};
const keyListeners = [];
globalThis.addEventListener = (type, fn) => { if (type === 'keydown') keyListeners.push(fn); };
globalThis.removeEventListener = (type, fn) => {
  const index = keyListeners.indexOf(fn);
  if (index >= 0) keyListeners.splice(index, 1);
};
function pressEscape() { for (const fn of [...keyListeners]) fn({ key: 'Escape' }); }

// Scripted Host: /prepare-dir can be held open so a cancel can land mid-flight.
const state = {
  targets: [{ id: 't1', name: '财经', host: '10.0.0.9', port: 22, username: 'root', identityFile: '', passwordEnv: '', remoteDir: '/srv/app', localDir: '' }],
  defaultId: '',
  prepareGate: null,
  prepareCalls: 0,
};
function json(value) {
  return { ok: true, status: 200, text: async () => JSON.stringify(value) };
}
globalThis.fetch = async (url, init) => {
  const path = String(url).replace('/remote-ssh', '');
  if (path === '/targets' && !(init && init.method)) {
    return json({ ok: true, targets: state.targets, defaultId: state.defaultId });
  }
  if (path === '/prepare-dir') {
    state.prepareCalls += 1;
    if (state.prepareGate) await state.prepareGate;
    return json({ ok: true, dir: '/Users/me/dsh-remote/t1' });
  }
  if (path === '/default') {
    state.defaultId = JSON.parse(init.body).target;
    return json({ ok: true, message: 'default' });
  }
  return json({ ok: true, message: 'ok' });
};

// Services the flow reaches through ctx.get().
const workspaceCalls = { create: [], rename: [] };
const services = {
  workspaces: {
    create: async (input) => { workspaceCalls.create.push(input); return { workspace: { workspaceId: 'ws-1' } }; },
    rename: async (...args) => { workspaceCalls.rename.push(args); return {}; },
  },
  uiWorkspace: { pickDirectory: async () => '/picked/dir' },
};

// ── load the real client bundle ─────────────────────────────────────────────
let captured = null;
globalThis.window = { __ModuleLoader__: { load: (spec) => { captured = spec; } } };
await import(source);

let Component = null;
const slotRegistry = {
  inject: (_name, factory) => {
    const result = factory();
    if (result && typeof result[Symbol.iterator] === 'function') { for (const _ of result) { /* drain */ } }
    return () => {};
  },
  register: (_spec, component) => { if (!Component) Component = component; return () => {}; },
};
captured.factory((id) => {
  if (id === 'react') return React;
  throw new Error(`unexpected require(${id})`);
}).apply({ get: (name) => services[name], slots: slotRegistry });
if (!Component) throw new Error('client bundle registered no flow component');

// ── render driver ───────────────────────────────────────────────────────────
let props = null;
let tree = null;
let outcome = { picked: [], cancelled: 0, errored: [] };

function renderOnce() {
  hookIndex = 0;
  dirty = false;
  tree = Component(props);
  for (const slot of hookList) {
    if (!slot || slot.kind !== 'effect' || !slot.dirty) continue;
    slot.dirty = false;
    if (slot.cleanup) { try { slot.cleanup(); } catch { /* ignore */ } }
    const cleanup = slot.fn();
    slot.cleanup = typeof cleanup === 'function' ? cleanup : undefined;
  }
}

async function pump(limit = 40) {
  for (let i = 0; i < limit; i += 1) {
    renderOnce();
    if (!dirty) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      renderOnce();
      if (!dirty) return;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/** Mount the flow the way the owner does: withdraw `open`, then raise it. */
async function openFlow() {
  outcome = { picked: [], cancelled: 0, errored: [] };
  workspaceCalls.create = [];
  workspaceCalls.rename = [];
  const base = {
    busy: false,
    onPicked: (path) => { outcome.picked.push(path); props.open = false; },
    onCancel: () => { outcome.cancelled += 1; props.open = false; },
    onError: (message) => outcome.errored.push(message),
  };
  props = { open: false, ...base };
  await pump();
  props = { open: true, ...base };
  await pump();
}

function walk(node, visit) {
  if (Array.isArray(node)) { for (const child of node) walk(child, visit); return; }
  if (node === null || node === undefined || typeof node !== 'object') return;
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}

function find(predicate) {
  let found = null;
  walk(tree, (node) => { if (!found && predicate(node)) found = node; });
  return found;
}

function button(label) {
  return find((node) => node.type === 'button' && typeof node.props.onClick === 'function' && (node.children || []).includes(label));
}

function click(node) {
  node.props.onClick({ target: node, currentTarget: node });
}

function clickBackdrop() {
  const modal = find((node) => node.type === 'div' && node.props.className === 'dshSsh_modal');
  if (!modal || typeof modal.props.onClick !== 'function') throw new Error('the modal does not handle backdrop clicks');
  modal.props.onClick({ target: modal, currentTarget: modal });
}

/** Step back to the chooser (present in every build), then cancel. */
async function cancelFromList() {
  click(button('返回'));
  await pump();
  click(button('取消'));
  await pump();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, ok) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) process.exitCode = 1;
}

// ── 1. the chooser's 取消 reports one outcome and nothing else ─────────────
await openFlow();
check('chooser offers 取消', Boolean(button('取消')));
click(button('取消'));
await pump();
check('chooser 取消 reports onCancel once', outcome.cancelled === 1);
check('chooser 取消 never picks a directory', outcome.picked.length === 0);

// ── 2. cancel mid-"打开" must not land ─────────────────────────────────────
let releasePrepare;
state.prepareGate = new Promise((resolve) => { releasePrepare = resolve; });
await openFlow();
click(button('远程工作区（1）…'));
await pump();
check('list shows the saved target', Boolean(button('打开')));
click(button('打开'));
await sleep(0);                       // /prepare-dir is now held open
await pump();
check('打开 shows an in-flight state', Boolean(button('打开中…')));
await cancelFromList();               // user dismisses mid-flight
releasePrepare();                     // the Host answers anyway
await sleep(20);
await pump();
check('mid-flight 取消 reports onCancel once', outcome.cancelled === 1);
check('mid-flight 取消 never adopts a directory', outcome.picked.length === 0);
check('mid-flight 取消 never creates a workspace', workspaceCalls.create.length === 0);
check('mid-flight 取消 never switches the default target', state.defaultId === '');
state.prepareGate = null;

// ── 3. the same flow without a dismissal still works ───────────────────────
state.defaultId = '';
await openFlow();
click(button('远程工作区（1）…'));
await pump();
click(button('打开'));
await sleep(30);
await pump();
check('normal 打开 adopts the directory', outcome.picked.length === 1);
check('normal 打开 creates the workspace', workspaceCalls.create.length === 1);
check('normal 打开 switches the default target', state.defaultId === 't1');

// ── 4. backdrop and Escape dismiss ─────────────────────────────────────────
await openFlow();
clickBackdrop();
await pump();
check('backdrop click cancels', outcome.cancelled === 1);
await openFlow();
pressEscape();
await pump();
check('Escape cancels', outcome.cancelled === 1);

// ── 5. a later open edge is armed again ────────────────────────────────────
state.defaultId = '';
await openFlow();
click(button('取消'));
await pump();
await openFlow();
click(button('远程工作区（1）…'));
await pump();
click(button('打开'));
await sleep(30);
await pump();
check('reopened flow still adopts', outcome.picked.length === 1);
check('reopened flow cancels nothing', outcome.cancelled === 0);

console.log(process.exitCode ? 'FAILED' : 'all client-flow cases passed');
