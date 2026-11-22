// Starts a fresh mcp-gateway process (bin/gw) with a temporary data directory.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
export const GW_BIN = path.join(REPO_ROOT, 'bin', 'gw');

export interface Gateway {
  /** Browser URL. Passkeys need a domain, not an IP, so this uses localhost. */
  url: string;
  /** Same server via 127.0.0.1 for Node-side API calls (avoids IPv6 localhost lookups). */
  apiUrl: string;
  adminKey?: string;
  dataDir: string;
  proc: ChildProcess;
  log: () => string;
  /** Resolves with the first log match, waiting up to timeoutMs. */
  waitForLog: (re: RegExp, timeoutMs?: number) => Promise<RegExpMatchArray>;
  stop: () => Promise<void>;
}

export function checkBinary(): void {
  if (!fs.existsSync(GW_BIN)) {
    throw new Error(
      `bin/gw not found. Build the dashboard and the binary first:\n  (cd web && npm ci && npm run build) && go build -o bin/gw ./cmd/gw\nor run "npm run build:all" in test/e2e.`,
    );
  }
  const dist = path.join(REPO_ROOT, 'web', 'dist', 'assets');
  if (!fs.existsSync(dist) || fs.readdirSync(dist).length === 0) {
    throw new Error('web/dist has no built assets. Run "npm run build" in web/ and then rebuild bin/gw so the dashboard is embedded.');
  }
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

function keygen(kind: 'master' | 'admin'): string {
  return execFileSync(GW_BIN, ['keygen', kind], { encoding: 'utf8' }).trim();
}

export async function startGateway(opts: { bootstrap: boolean }): Promise<Gateway> {
  checkBinary();
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-e2e-'));
  const adminKey = opts.bootstrap ? keygen('admin') : undefined;
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    GW_LISTEN: `127.0.0.1:${port}`,
    GW_PUBLIC_URL: `http://localhost:${port}`,
    GW_DATA_DIR: dataDir,
    GW_KEY_PROVIDER: 'env',
    GW_MASTER_KEY: keygen('master'),
    GW_LOG_LEVEL: 'info',
  };
  if (adminKey) env.GW_BOOTSTRAP_ADMIN_KEY = adminKey;
  const proc = spawn(GW_BIN, ['serve'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const waiters: { re: RegExp; resolve: (m: RegExpMatchArray) => void }[] = [];
  const onData = (b: Buffer) => {
    out += b.toString();
    for (let i = waiters.length - 1; i >= 0; i--) {
      const m = out.match(waiters[i].re);
      if (m) {
        waiters[i].resolve(m);
        waiters.splice(i, 1);
      }
    }
  };
  proc.stdout?.on('data', onData);
  proc.stderr?.on('data', onData);
  let exited = false;
  proc.on('exit', () => (exited = true));

  const apiUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  for (;;) {
    if (exited) throw new Error(`gateway exited during startup:\n${out}`);
    try {
      const r = await fetch(apiUrl + '/readyz');
      if (r.status === 200) break;
    } catch {
      /* not listening yet */
    }
    if (Date.now() > deadline) {
      proc.kill('SIGKILL');
      throw new Error(`gateway did not become ready:\n${out}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  return {
    url: `http://localhost:${port}`,
    apiUrl,
    adminKey,
    dataDir,
    proc,
    log: () => out,
    waitForLog: (re, timeoutMs = 5000) => {
      const m = out.match(re);
      if (m) return Promise.resolve(m);
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`log line ${re} not seen in:\n${out}`)), timeoutMs);
        waiters.push({ re, resolve: (mm) => { clearTimeout(t); resolve(mm); } });
      });
    },
    stop: async () => {
      if (!exited) {
        const done = new Promise<void>((r) => proc.once('exit', () => r()));
        proc.kill('SIGTERM');
        const t = setTimeout(() => proc.kill('SIGKILL'), 5000);
        await done;
        clearTimeout(t);
      }
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}
