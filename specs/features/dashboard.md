# UI: Admin dashboard

The dashboard is a single-page app served at `/admin`, using only the Admin API (CTL-040).

## Acceptance criteria

- **UI-001** Visiting `/admin` without a session shows the login page. After login, the Overview page shows counts for servers, AI tools, calls today and blocked calls, plus a "Needs your attention" list.
- **UI-002** First-run setup: `/admin/setup?token=…` lets the first user register (passkey) and lands on the Overview.
- **UI-003** Servers page: list servers with transport, tool count and health badge; add a server from the catalog or manually; edit; delete with confirmation.
- **UI-004** Server detail: list the server's tools with read-only/write badges and pin status; set or replace a credential (the value is never displayed again).
- **UI-005** AI tools page: list clients with profile, last seen and call count; create a static token (shown once with a copy button and a ready-to-paste config snippet for Claude Code, Codex and Cursor); revoke with confirmation.
- **UI-006** Profiles page: list profiles; edit rules in a table (pattern, when, action) with add, delete and reorder; save validates and shows server-side errors inline.
- **UI-007** Rule simulator: choose profile + tool name + read-only flag, and see the decision and which rule matched.
- **UI-008** Approvals page: pending approvals appear live (SSE) without refresh; Approve and Deny buttons release the waiting call; the sidebar badge shows the pending count.
- **UI-009** Tool changes page: shows old vs new description as a diff; Accept or Reject.
- **UI-010** Activity page: table of audit events, newest first, with filters (server, client, decision) and "Load more"; "Verify chain" shows the result.
- **UI-011** Security page: key provider name and strength, signing key age with Rotate button, export and import config.
- **UI-012** Users page (owner/admin): list users and roles; change role; create admin API key.
- **UI-013** Viewer role sees every page read-only: no create, edit, delete or decide buttons.
- **UI-014** Works in light and dark mode, is usable at 375 px width, and every interactive control is reachable by keyboard with a visible focus ring.
- **UI-015** Errors from the API are shown as a readable message; the UI never shows raw stack traces.
