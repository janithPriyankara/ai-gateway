#!/usr/bin/env python3
"""Generates docs/architecture.drawio. Run: python3 docs/gen_architecture.py"""
import html
from pathlib import Path

cells = []
_id = [10]


def nid():
    _id[0] += 1
    return f"n{_id[0]}"


def esc(s):
    return html.escape(s, quote=True)


def box(label, x, y, w, h, style, parent="1"):
    i = nid()
    cells.append(
        f'<mxCell id="{i}" value="{esc(label)}" style="{style}" vertex="1" parent="{parent}">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>'
    )
    return i


def edge(src, dst, label="", style="", parent="1", points=None):
    i = nid()
    base = ("edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;html=1;"
            "endArrow=block;endFill=1;strokeWidth=1.5;fontSize=11;labelBackgroundColor=#ffffff;")
    pts = ""
    if points:
        pts = '<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in points) + "</Array>"
    cells.append(
        f'<mxCell id="{i}" value="{esc(label)}" style="{base}{style}" edge="1" parent="{parent}" '
        f'source="{src}" target="{dst}"><mxGeometry relative="1" as="geometry">{pts}</mxGeometry></mxCell>'
    )
    return i


# palette
CLIENT = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=12;"
EDGEBAR = "rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;fontSize=12;horizontal=0;fontStyle=1;"
CONTAINER = ("rounded=1;whiteSpace=wrap;html=1;fillColor=#fafafa;strokeColor=#333333;dashed=1;"
             "verticalAlign=top;align=left;spacingLeft=12;spacingTop=8;fontSize=15;fontStyle=1;arcSize=3;")
DATAPLANE = ("rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;verticalAlign=top;"
             "align=left;spacingLeft=10;spacingTop=6;fontSize=13;fontStyle=1;arcSize=4;")
CTRL = ("rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;verticalAlign=top;"
        "align=left;spacingLeft=10;spacingTop=6;fontSize=13;fontStyle=1;arcSize=6;")
COMP = "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#999999;fontSize=11;"
DB = "shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=8;fillColor=#f5f5f5;strokeColor=#666666;fontSize=11;"
UP = "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontSize=12;"
PLUG = "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;fontSize=11;"
NOTE = "text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontSize=12;"
GROUP = "rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#b85450;dashed=1;verticalAlign=top;fontSize=12;fontStyle=1;"

# title
box("<b style='font-size:20px'>mcp-gateway: architecture</b><br>"
    "One login per AI tool. One login per MCP server. Every call authenticated, authorized, credential-injected and audited.",
    40, 10, 1500, 50, NOTE)

# ---- clients ----
box("AI clients", 40, 80, 170, 24, "text;html=1;fontStyle=1;fontSize=14;")
cc = box("Claude Code<br><i>OAuth 2.1 + PKCE</i>", 40, 110, 170, 50, CLIENT)
cd = box("Claude Desktop / claude.ai<br><i>remote connector</i>", 40, 175, 170, 50, CLIENT)
cx = box("Codex CLI<br><i>static gw_ token</i>", 40, 240, 170, 50, CLIENT)
cu = box("Cursor / VS Code / others<br><i>Streamable HTTP</i>", 40, 305, 170, 50, CLIENT)
br = box("Admin browser<br><i>dashboard, passkey login</i>", 40, 470, 170, 50,
         "rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;fontSize=12;")

# ---- edge ----
tls = box("TLS edge: Caddy / Cloudflare Tunnel / Tailscale (optional)", 250, 110, 40, 410, EDGEBAR)

# ---- main container ----
main = box("mcp-gateway: one Go binary (gw serve --services=all) or 4 containers (microservices mode)",
           330, 80, 900, 690, CONTAINER)

# data plane
dp = box("Data plane: gateway service (stateless, horizontally scalable)  POST /mcp", 350, 120, 860, 230, DATAPLANE)
a1 = box("1. AuthN middleware<br>verify JWT (JWKS cache) or<br>static token → Identity", 370, 160, 150, 70, COMP)
a2 = box("2. Policy engine<br>first-match rules<br>allow / ask / deny + rate limit", 540, 160, 150, 70, COMP)
a3 = box("3. Router / aggregator<br>namespaced tools<br>github__create_issue", 710, 160, 150, 70, COMP)
a4 = box("4. Tool-pin check<br>sha256(name+desc+schema)<br>quarantine on drift", 880, 160, 150, 70, COMP)
a5 = box("5. Credential injector<br>per-user upstream token<br>(never client token)", 1050, 160, 145, 70, COMP)
a6 = box("Upstream pool<br>HTTP (Streamable) + stdio (sandboxed)<br>circuit breaker, timeouts, read-only retry", 710, 255, 320, 70, COMP)
a7 = box("6. Redactor + audit emitter<br>scrub secrets, async batch", 370, 255, 320, 70, COMP)
edge(a1, a2); edge(a2, a3); edge(a3, a4); edge(a4, a5)
edge(a5, a6, style="exitX=0.5;exitY=1;entryX=1;entryY=0.5;")

# control plane
cp_label = box("Control plane", 350, 365, 200, 24, "text;html=1;fontStyle=1;fontSize=14;")
au = box("Auth service", 350, 395, 270, 300, CTRL)
box("OAuth 2.1 authorization server<br>DCR · PKCE S256 · refresh rotation", 365, 430, 240, 44, COMP)
box("Protected Resource Metadata<br>/.well-known/* · JWKS (ES256)", 365, 482, 240, 44, COMP)
box("Passkeys (WebAuthn) · bootstrap token<br>external OIDC IdP (optional)", 365, 534, 240, 44, COMP)
box("Static client tokens (argon2id hashed)<br>signing-key rotation (90 days)", 365, 586, 240, 44, COMP)
audb = box("auth.db", 450, 640, 70, 45, DB)

va = box("Vault service", 640, 395, 270, 300, CTRL)
box("Envelope encryption<br>AES-256-GCM DEK per secret", 655, 430, 240, 44, COMP)
box("Upstream OAuth connect<br>(auth code + PKCE as a client)", 655, 482, 240, 44, COMP)
box("Token refresher<br>refresh at 80% TTL · needs_reauth", 655, 534, 240, 44, COMP)
box("KeyProvider port<br>wrap / unwrap / health", 655, 586, 240, 44, COMP)
vadb = box("vault.db", 740, 640, 70, 45, DB)

co = box("Control service", 930, 395, 280, 300, CTRL)
box("Admin REST API /admin/api/v1<br>OpenAPI · SSE live events", 945, 430, 250, 44, COMP)
box("Dashboard SPA (React, embedded)<br>RBAC: owner / admin / member / viewer", 945, 482, 250, 44, COMP)
box("Servers · profiles · rules · catalog<br>config snapshot (versioned) → gateway", 945, 534, 250, 44, COMP)
box("Approvals broker · tool pins<br>audit log (hash chain)", 945, 586, 250, 44, COMP)
codb = box("control.db", 1035, 640, 80, 45, DB)

box("<b>Ports and adapters:</b> the gateway depends only on interfaces (Authenticator, ConfigSource, "
    "CredentialProvider, AuditSink, ApprovalBroker). Monolith mode wires in-process adapters; "
    "microservices mode wires internal HTTP clients (service token + mTLS-ready). Database per service: SQLite (WAL).",
    350, 702, 860, 60, NOTE)

# ---- upstream ----
box("MCP servers (upstream)", 1290, 80, 220, 24, "text;html=1;fontStyle=1;fontSize=14;")
u1 = box("GitHub MCP<br><i>OAuth</i>", 1290, 110, 220, 46, UP)
u2 = box("Notion MCP<br><i>OAuth</i>", 1290, 166, 220, 46, UP)
u3 = box("Slack MCP<br><i>OAuth</i>", 1290, 222, 220, 46, UP)
u4 = box("Jenkins MCP<br><i>API key header</i>", 1290, 278, 220, 46, UP)
u5 = box("Postgres / filesystem<br><i>local stdio, sandboxed child</i>", 1290, 334, 220, 46, UP)
idp = box("Upstream OAuth servers<br>(github.com, notion.so …)", 1290, 470, 220, 50, UP)

# ---- plugins ----
kp = box("KeyProvider plugins", 640, 850, 590, 110, GROUP)
for i, (n, x) in enumerate([("macOS Keychain", 655), ("Windows DPAPI", 770), ("Linux TPM2<br>systemd-creds", 885),
                             ("Docker / K8s secret", 1000), ("Passphrase<br>argon2id", 1115)]):
    box(n, x, 885, 100, 40, PLUG)
box("+ AWS KMS · GCP KMS · Azure Key Vault · Vault/OpenBao Transit", 655, 932, 560, 20, "text;html=1;fontSize=11;")

nt = box("Notifier plugins", 1290, 600, 220, 160, GROUP)
for i, n in enumerate(["OS notification", "Web push / dashboard", "ntfy · Telegram", "Slack · email"]):
    box(n, 1305, 630 + i * 32, 190, 26, PLUG)

# ---- deployment legend ----
box("<b>Deployment modes</b><br>"
    "• <b>Personal:</b> gw serve on 127.0.0.1 (launchd / systemd / Windows service)<br>"
    "• <b>Home lab / VPS:</b> docker compose up (all-in-one container)<br>"
    "• <b>Microservices:</b> docker compose -f deploy/compose.split.yml up<br>"
    "&nbsp;&nbsp;gateway ×N (stateless) + auth + vault + control",
    40, 850, 560, 110, "rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;align=left;spacingLeft=10;fontSize=12;verticalAlign=top;spacingTop=6;")

# ---- edges ----
for c in (cc, cd, cx, cu):
    edge(c, tls, style="exitX=1;exitY=0.5;entryX=0;")
edge(br, tls, style="exitX=1;exitY=0.5;entryX=0;")
edge(tls, a1, "MCP + Bearer", style="exitX=1;exitY=0.2;entryX=0;entryY=0.5;")
edge(tls, au, "OAuth · passkey", style="exitX=1;exitY=0.62;entryX=0;entryY=0.25;dashed=1;")
edge(tls, co, "Admin API (session)", style="exitX=0.5;exitY=1;entryX=0.5;entryY=1;dashed=1;",
     points=[(270, 790), (1070, 790)])
edge(a1, au, "JWKS / verify", style="exitX=0.5;exitY=1;entryX=0.25;entryY=0;dashed=1;")
edge(a5, va, "GetCredential", style="exitX=0.5;exitY=1;entryX=0.75;entryY=0;dashed=1;",
     points=[(1122, 360), (842, 360)])
edge(a6, co, "snapshot · audit · approvals", style="exitX=0.75;exitY=1;entryX=0.5;entryY=0;dashed=1;",
     points=[(950, 375), (1070, 375)])
for u in (u1, u2, u3, u4, u5):
    edge(a6, u, style="exitX=1;exitY=0.5;entryX=0;entryY=0.5;", points=[(1250, 290)])
edge(va, idp, "OAuth connect + refresh", style="exitX=1;exitY=0.06;entryX=0;entryY=0.5;dashed=1;",
     points=[(920, 413), (920, 385), (1260, 385), (1260, 495)])
edge(va, kp, "wrap / unwrap DEK", style="exitX=0.5;exitY=1;entryX=0.2;entryY=0;")
edge(co, nt, "ask → notify", style="exitX=1;exitY=0.75;entryX=0;entryY=0.4;dashed=1;")
xml = ('<mxfile host="app.diagrams.net"><diagram id="arch" name="Architecture">'
       '<mxGraphModel dx="1600" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" '
       'arrows="1" fold="1" page="1" pageScale="1" pageWidth="1600" pageHeight="1000" math="0" shadow="0">'
       '<root><mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(cells) +
       '</root></mxGraphModel></diagram></mxfile>')
out = Path(__file__).with_name("architecture.drawio")
out.write_text(xml)
print(out)
import json as _json
viewer = Path(__file__).with_name("architecture.html")
cfg = _json.dumps({"highlight": "#0000ff", "nav": True, "resize": True, "toolbar": "zoom layers lightbox", "edit": "_blank", "xml": xml})
viewer.write_text(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>mcp-gateway architecture</title>"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>body{margin:0;padding:16px;font:14px system-ui;background:#fff}</style></head>"
    "<body><div class=\"mxgraph\" style=\"max-width:100%;border:1px solid #e5e5e5\" data-mxgraph=\"" + html.escape(cfg, quote=True) + "\"></div>"
    "<script src=\"https://viewer.diagrams.net/js/viewer-static.min.js\"></script></body></html>")
print(viewer)
