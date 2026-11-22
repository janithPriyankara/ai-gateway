// Starts one gateway (with a bootstrap owner API key) and the upstream MCP fixture
// for the whole run. Tests read their URLs from environment variables.
import type { FullConfig } from '@playwright/test';
import { checkBinary, startGateway } from './support/gateway';
import { startFixture } from './support/mcp-fixture';

export default async function globalSetup(_config: FullConfig) {
  checkBinary();
  const fixture = await startFixture();
  const gw = await startGateway({ bootstrap: true });
  process.env.GW_URL = gw.url;
  process.env.GW_API_URL = gw.apiUrl;
  process.env.GW_ADMIN_KEY = gw.adminKey ?? '';
  process.env.FIXTURE_URL = fixture.url;
  return async () => {
    await gw.stop();
    await fixture.close();
  };
}
