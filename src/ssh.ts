// SSH transport: connection, command execution, SFTP read/write.
// Extracted from index.ts so the tool layer, the Remote-UI route layer, and the
// connectivity test all share one connection implementation.
import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Connection settings for one SSH target (no secrets beyond an env var name). */
export interface SshConfig {
  host: string;
  port: number;
  username: string;
  identityFile: string;
  /** One-off password (Remote UI test only); never persisted by this plugin. */
  password: string;
  /** Name of the environment variable holding the password, when password auth is used. */
  passwordEnv?: string;
  remoteDir: string;
}

export interface SshStream {
  on(event: 'data', cb: (data: { toString(): string }) => void): void;
  on(event: 'close', cb: (code: number) => void): void;
  on(event: 'error', cb: (error: Error) => void): void;
  stderr: { on(event: 'data', cb: (data: { toString(): string }) => void): void };
  /** ssh2 ClientChannel: RFC 4254 "signal" request, forwards SIG* to the remote command. */
  signal?(name: string): void;
  /** ssh2 ClientChannel: closes the channel (the remote command gets SIGHUP). */
  close?(): void;
}

export interface SftpLike {
  readFile(path: string, encoding: string, cb: (err: Error | undefined, content: Buffer | string) => void): void;
  writeFile(path: string, content: string, cb: (err: Error | undefined) => void): void;
  /** ssh2 SFTP session: ends this session only, never the shared connection. */
  end?(): void;
}

// ── Cooperative cancellation ─────────────────────────────────────────────────
// DSH dispatches every tool body with the caller-owned `exec.signal` and expects
// the body to observe it: a cancel must quiesce the body, not just abandon it.
// The SSH calls below therefore stop their channel/SFTP session on abort, so
// pressing 停止/取消 in the UI ends the remote command instead of leaving it to
// run until its own timeout on the far side.

/** An abort-shaped error (name `AbortError`) so callers can tell it from a transport failure. */
export function abortError(message = 'ssh call cancelled'): Error {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/** Run `onAbort` when `signal` aborts; returns the disposer (no-op for no signal). */
function listenAbort(signal: AbortSignal | undefined, onAbort: () => void): () => void {
  if (!signal) return () => { /* nothing to detach */ };
  if (signal.aborted) {
    onAbort();
    return () => { /* already fired */ };
  }
  signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}

/**
 * Await `promise` but reject as soon as `signal` aborts. The promise itself keeps
 * running (a pooled SSH connection is shared, so one cancelled call must not tear
 * it down for its siblings); only this caller stops waiting.
 */
export function awaitWithSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise<T>((resolve, reject) => {
    const off = listenAbort(signal, () => reject(abortError()));
    promise.then((value) => { off(); resolve(value); }, (error: unknown) => { off(); reject(error); });
  });
}

export interface KeyboardInteractivePrompt {
  prompt: string;
  echo: boolean;
}

export interface SshClientLike {
  on(event: 'ready', cb: () => void): SshClientLike;
  on(event: 'error', cb: (error: Error) => void): SshClientLike;
  on(
    event: 'keyboard-interactive',
    cb: (
      name: string,
      instructions: string,
      lang: string,
      prompts: KeyboardInteractivePrompt[],
      finish: (responses: string[]) => void,
    ) => void,
  ): SshClientLike;
  connect(config: Record<string, unknown>): void;
  exec(command: string, cb: (err: Error | undefined, stream: SshStream) => void): void;
  sftp(cb: (err: Error | undefined, sftp: SftpLike) => void): void;
  end(): void;
}

export type SshClientCtor = new () => SshClientLike;

let ssh2ClientCtor: SshClientCtor | null = null;
let ssh2Failed = false;

/** Load `ssh2` once; a load failure is cached so tools degrade instead of retrying forever. */
export async function loadSsh2ClientCtor(): Promise<SshClientCtor | null> {
  if (ssh2ClientCtor) return ssh2ClientCtor;
  if (ssh2Failed) return null;
  try {
    const mod = (await import('ssh2')) as unknown as { Client: SshClientCtor };
    ssh2ClientCtor = mod.Client;
    return ssh2ClientCtor;
  } catch {
    ssh2Failed = true;
    return null;
  }
}

export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return p;
}

/** Default private keys ssh(1) would try, in its preference order. */
function defaultIdentityFiles(): string[] {
  return ['id_ed25519', 'id_ecdsa', 'id_rsa'].map((f) => join(homedir(), '.ssh', f)).filter((p) => existsSync(p));
}

/**
 * Build the ssh2 connect options for one target.
 * @param cfg - resolved target settings.
 * @param password - already-resolved password (credential store, env, or a one-off); empty disables password auth.
 */
export function connectOptions(cfg: SshConfig, password: string): Record<string, unknown> {
  const options: Record<string, unknown> = {
    host: cfg.host,
    port: cfg.port,
    username: cfg.username || process.env.USER || process.env.LOGNAME || '',
    readyTimeout: 20000,
  };
  if (cfg.identityFile) {
    options.privateKey = readFileSync(expandHome(cfg.identityFile));
  } else if (password) {
    options.password = password;
    // Without this, ssh2 never offers keyboard-interactive and a PAM/AD server
    // answers "All configured authentication methods failed" even though ssh(1)
    // logs in with the same password.
    options.tryKeyboard = true;
  } else if (process.env.SSH_AUTH_SOCK) {
    options.agent = process.env.SSH_AUTH_SOCK;
  } else {
    const keys: Buffer[] = [];
    for (const p of defaultIdentityFiles()) {
      try {
        keys.push(readFileSync(p));
      } catch { /* unreadable key: let the next candidate try */ }
    }
    if (keys.length > 0) options.privateKey = keys;
  }
  return options;
}

/**
 * Open one SSH connection and resolve once the handshake reports `ready`.
 * An aborted `signal` ends the half-open connection, so a cancelled one-off
 * (connection test) leaves nothing dialing in the background.
 */
export function connectSsh(Ctor: SshClientCtor, cfg: SshConfig, password = '', signal?: AbortSignal): Promise<SshClientLike> {
  return new Promise((resolve, reject) => {
    let options: Record<string, unknown>;
    try {
      options = connectOptions(cfg, password);
    } catch (e) {
      reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    const client = new Ctor();
    let settled = false;
    let offAbort: () => void = () => { /* attached below */ };
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      offAbort();
      try { client.end(); } catch { /* the handshake never started */ }
      reject(error);
    };
    offAbort = listenAbort(signal, () => fail(abortError('ssh connect cancelled')));
    client.on('error', (error) => {
      // ssh2 reports every rejected method with one generic sentence; name what
      // was actually attempted so a credential problem is distinguishable from
      // a server that offers no method we support.
      const attempted: string[] = [];
      if (options.privateKey !== undefined) attempted.push('private key');
      if (typeof options.password === 'string') attempted.push('password', 'keyboard-interactive');
      if (options.agent !== undefined) attempted.push('ssh-agent');
      if (attempted.length === 0) attempted.push('ssh-agent', 'default keys');
      const hint = /authentication methods failed/i.test(error.message)
        ? `${error.message}（已尝试：${attempted.join('、')}；用户名 ${String(options.username)}）`
        : error.message;
      fail(new Error(hint));
    });
    if (password) {
      client.on('keyboard-interactive', (_name, _instructions, _lang, prompts, finish) => {
        finish(prompts.map(() => password));
      });
    }
    client.on('ready', () => {
      if (settled) return;
      settled = true;
      offAbort();
      resolve(client);
    });
    try {
      client.connect(options);
    } catch (e) {
      fail(e instanceof Error ? e : new Error(String(e)));
    }
  });
}

/** Prove one target is reachable and authenticated, then disconnect. */
export async function testConnection(cfg: SshConfig, password = '', signal?: AbortSignal): Promise<{ ok: boolean; message: string }> {
  const Ctor = await loadSsh2ClientCtor();
  if (!Ctor) return { ok: false, message: 'ssh2 不可用（插件目录缺少 node_modules，请先 pnpm install）' };
  const started = Date.now();
  try {
    const client = await connectSsh(Ctor, cfg, password, signal);
    const identifying = `${cfg.username || process.env.USER || ''}@${cfg.host}:${cfg.port}`;
    client.end();
    return { ok: true, message: `已连通 ${identifying}（${Date.now() - started}ms）` };
  } catch (e) {
    if (isAbortError(e)) throw e;
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Resolve a tool-supplied path against the configured remote working directory. */
export function resolveRemotePath(remotePath: string, remoteDir: string): string {
  if (!remoteDir || remotePath.startsWith('/') || remotePath.startsWith('~')) return remotePath;
  return `${remoteDir.replace(/\/+$/, '')}/${remotePath}`;
}

/** Run the command from the configured remote working directory. */
export function withRemoteDir(command: string, remoteDir: string): string {
  if (!remoteDir) return command;
  return `cd ${shellQuote(remoteDir)} && ${command}`;
}

/**
 * Stop one running remote command: closing the channel alone leaves the remote
 * process alive (sshd only hangs up pty sessions), so ask the server to forward
 * SIGTERM first — RFC 4254 "signal" — and drop the channel right after.
 */
function stopStream(stream: SshStream | undefined): void {
  if (!stream) return;
  try { stream.signal?.('TERM'); } catch { /* server refused the request */ }
  try { stream.close?.(); } catch { /* channel already gone */ }
}

/**
 * Run one command over an existing connection.
 * @param client - pooled SSH connection.
 * @param command - command line.
 * @param timeoutMs - local timeout for the whole call.
 * @param remoteDir - directory to `cd` into first.
 * @param signal - caller cancellation: aborting closes the channel, which
 *   makes sshd hang up the remote command instead of letting it keep running.
 */
export function sshExec(client: SshClientLike, command: string, timeoutMs: number, remoteDir: string, signal?: AbortSignal): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    let settled = false;
    let stream: SshStream | undefined;
    let offAbort: () => void = () => { /* attached below */ };
    // One exit point: clears the timeout, detaches the abort listener, then settles.
    const finish = (settle: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      offAbort();
      settle();
    };
    const timer = setTimeout(() => {
      finish(() => {
        client.end();
        reject(new Error(`ssh-exec timed out after ${timeoutMs}ms`));
      });
    }, timeoutMs);
    offAbort = listenAbort(signal, () => {
      finish(() => {
        stopStream(stream);
        reject(abortError());
      });
    });
    client.exec(withRemoteDir(command, remoteDir), (err, next) => {
      if (err) return finish(() => reject(err));
      stream = next;
      // The cancel may have landed between `exec` and this callback: stop the
      // channel we just acquired instead of leaving the command running.
      if (settled) {
        stopStream(next);
        return;
      }
      let stdout = '', stderr = '';
      next.on('data', (d) => { stdout += d.toString(); });
      next.stderr.on('data', (d) => { stderr += d.toString(); });
      // ssh2 streams close with an exit-code 'close' event carrying the code
      next.on('close', (code) => finish(() => resolve({ stdout, stderr, exitCode: code })));
      next.on('error', (e) => finish(() => reject(e)));
    });
  });
}

export function sshRead(client: SshClientLike, remotePath: string, remoteDir: string, signal?: AbortSignal): Promise<{ content: string; path: string }> {
  const target = resolveRemotePath(remotePath, remoteDir);
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    let settled = false;
    let sftp: SftpLike | undefined;
    let offAbort: () => void = () => { /* attached below */ };
    const finish = (settle: () => void): void => {
      if (settled) return;
      settled = true;
      offAbort();
      settle();
    };
    offAbort = listenAbort(signal, () => finish(() => {
      try { sftp?.end?.(); } catch { /* session already gone */ }
      reject(abortError());
    }));
    client.sftp((err, session) => {
      if (err) return finish(() => reject(err));
      sftp = session;
      if (settled) {
        try { session.end?.(); } catch { /* already closed */ }
        return;
      }
      session.readFile(target, 'utf8', (readErr, content) => {
        if (readErr) return finish(() => reject(readErr));
        finish(() => resolve({ content: typeof content === 'string' ? content : content.toString('utf8'), path: target }));
      });
    });
  });
}

export function sshWrite(client: SshClientLike, remotePath: string, content: string, remoteDir: string, signal?: AbortSignal): Promise<{ success: boolean; path: string }> {
  const target = resolveRemotePath(remotePath, remoteDir);
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    let settled = false;
    let sftp: SftpLike | undefined;
    let offAbort: () => void = () => { /* attached below */ };
    const finish = (settle: () => void): void => {
      if (settled) return;
      settled = true;
      offAbort();
      settle();
    };
    offAbort = listenAbort(signal, () => finish(() => {
      try { sftp?.end?.(); } catch { /* session already gone */ }
      reject(abortError());
    }));
    client.sftp((err, session) => {
      if (err) return finish(() => reject(err));
      sftp = session;
      if (settled) {
        try { session.end?.(); } catch { /* already closed */ }
        return;
      }
      session.writeFile(target, content, (writeErr) => {
        if (writeErr) return finish(() => reject(writeErr));
        finish(() => resolve({ success: true, path: target }));
      });
    });
  });
}

// ── Remote directory browsing ────────────────────────────────────────────────

export interface RemoteDirEntry {
  name: string;
  dir: boolean;
}

export interface RemoteDirListing {
  /** Absolute path the listing resolved to. */
  path: string;
  /** Parent directory, or the path itself at the root. */
  parent: string;
  entries: RemoteDirEntry[];
}

/** Quote one path for `sh`, expanding a leading `~` the way a shell would. */
function cdTarget(path: string): string {
  const trimmed = path.trim();
  if (trimmed === '' || trimmed === '~' || trimmed === '$HOME') return '"$HOME"';
  if (trimmed.startsWith('~/')) return `"$HOME"/${shellQuote(trimmed.slice(2))}`;
  return shellQuote(trimmed);
}

function parentOf(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  if (trimmed === '' || trimmed === '/') return '/';
  const cut = trimmed.slice(0, trimmed.lastIndexOf('/'));
  return cut === '' ? '/' : cut;
}

/**
 * List one remote directory over the existing exec channel. `ls -A1p` marks
 * directories with a trailing slash, which keeps parsing trivial and needs no
 * SFTP negotiation.
 * @param client - connected SSH client.
 * @param dir - directory to list; empty starts from `remoteDir`, then `$HOME`.
 * @param remoteDir - the target's configured working directory.
 * @param signal - caller cancellation, forwarded to the underlying exec.
 * @returns the resolved path, its parent, and its entries (directories first).
 */
export async function sshListDir(client: SshClientLike, dir: string, remoteDir: string, signal?: AbortSignal): Promise<RemoteDirListing> {
  const start = dir.trim() !== '' ? dir : (remoteDir.trim() !== '' ? remoteDir : '$HOME');
  const script = `cd ${cdTarget(start)} 2>/dev/null || exit 9; printf '%s\\n' "$PWD"; ls -A1p`;
  const { stdout, stderr, exitCode } = await sshExec(client, script, 15000, '', signal);
  if (exitCode !== 0) {
    throw new Error(stderr.trim() || `无法进入目录 ${start}（exit ${exitCode}）`);
  }
  const lines = stdout.split('\n').map((line) => line.replace(/\r$/, ''));
  const path = (lines.shift() ?? '').trim();
  const entries = lines
    .filter((line) => line !== '')
    .map((line) => ({ name: line.replace(/\/+$/, ''), dir: line.endsWith('/') }))
    .filter((entry) => entry.name !== '' && entry.name !== '.' && entry.name !== '..')
    .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));
  return { path, parent: parentOf(path), entries };
}
