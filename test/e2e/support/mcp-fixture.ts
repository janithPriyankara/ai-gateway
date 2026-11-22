// A tiny upstream MCP server for the e2e tests (Streamable HTTP, stateless).
//
// Every path /mcp/<instance> is an independent server with the same tools, so each
// test can register its own gateway server without affecting the others.
// Tool descriptions can be changed at runtime (tool pinning test, UI-009):
//   POST /control/<instance>/description  {"tool": "search_code", "description": "..."}
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const DEFAULTS: Record<string, string> = {
  list_issues: 'List open issues in the repository.',
  merge_pr: 'Merge a pull request.',
  search_code: 'Search the code in the repository for a text query.',
};

const descriptions = new Map<string, string>(); // `${instance}:${tool}` -> description

function desc(instance: string, tool: string): string {
  return descriptions.get(`${instance}:${tool}`) ?? DEFAULTS[tool];
}

function buildServer(instance: string): McpServer {
  const s = new McpServer({ name: `fixture-${instance}`, version: '1.0.0' });
  s.registerTool(
    'list_issues',
    { description: desc(instance, 'list_issues'), inputSchema: { state: z.string().optional() }, annotations: { readOnlyHint: true } },
    async () => ({ content: [{ type: 'text', text: 'issue #1: fix the build' }] }),
  );
  s.registerTool(
    'merge_pr',
    { description: desc(instance, 'merge_pr'), inputSchema: { number: z.number() }, annotations: { readOnlyHint: false } },
    async ({ number }) => ({ content: [{ type: 'text', text: `merged pull request #${number}` }] }),
  );
  s.registerTool(
    'search_code',
    { description: desc(instance, 'search_code'), inputSchema: { query: z.string() }, annotations: { readOnlyHint: true } },
    async ({ query }) => ({ content: [{ type: 'text', text: `no results for ${query}` }] }),
  );
  return s;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', (c: string) => (data += c));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

export interface Fixture {
  url: string;
  close: () => Promise<void>;
}

export async function startFixture(): Promise<Fixture> {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      const ctl = /^\/control\/([\w-]+)\/description$/.exec(url.pathname);
      if (ctl && req.method === 'POST') {
        const body = JSON.parse(await readBody(req)) as { tool: string; description: string };
        descriptions.set(`${ctl[1]}:${body.tool}`, body.description);
        res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
        return;
      }
      const m = /^\/mcp\/([\w-]+)$/.exec(url.pathname);
      if (!m) {
        res.writeHead(404).end();
        return;
      }
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST' }).end();
        return;
      }
      // Instances named basic_* behave like Jenkins: only HTTP Basic e2e-user:e2e-token gets in.
      if (m[1].startsWith('basic_') && req.headers.authorization !== 'Basic ' + Buffer.from('e2e-user:e2e-token').toString('base64')) {
        res.writeHead(401, { 'content-type': 'text/plain' }).end('Unauthorized');
        return;
      }
      const raw = await readBody(req);
      const mcp = buildServer(m[1]);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => {
        void transport.close();
        void mcp.close();
      });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, raw ? JSON.parse(raw) : undefined);
    } catch (e) {
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(String(e));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
