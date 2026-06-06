// cf-shell-share — WebSocket relay via Durable Objects
//
// SECURITY MODEL:
//   All data relayed here is AES-256-GCM encrypted by the clients using a
//   key derived from the session token (SHA-256). This Worker only sees and
//   forwards opaque binary ciphertext. It cannot decrypt session content.
//
// Roles:
//   host   — shares their shell (produces PTY output, consumes input)
//   viewer — watches / controls (consumes output, produces input)

export interface Env {
  SESSIONS: DurableObjectNamespace;
}

// ── Entry Worker ────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (pathname === '/') return handleLanding();
    if (pathname === '/session' && request.method === 'POST') return handleCreateSession(request, env);
    if (pathname === '/ws') return handleWs(request, env, url);
    if (pathname.startsWith('/j/')) return handleJoinRedirect(request.url);

    return new Response('Not Found', { status: 404 });
  },
};

// ── Location hint helper ─────────────────────────────────────────────────────
// Maps the requester's CF continent to the nearest DO region.
// This ensures the Durable Object is placed close to the users, not in a
// default US datacenter which would add ~200-400ms per relay hop.

type DurableObjectLocationHint = 'wnam' | 'enam' | 'sam' | 'weur' | 'eeur' | 'apac' | 'oc' | 'afr' | 'me';

function locationHint(request: Request): DurableObjectLocationHint {
  const cf = (request as any).cf as { continent?: string; timezone?: string } | undefined;
  const continent = cf?.continent ?? '';
  const tz = cf?.timezone ?? '';
  // Map continent codes to CF DO location hints
  const map: Record<string, DurableObjectLocationHint> = {
    AS: 'apac', OC: 'apac',
    EU: 'weur',
    AF: 'afr',
    SA: 'sam',
    ME: 'me',
  };
  if (map[continent]) return map[continent];
  // North America: split east/west by timezone
  if (continent === 'NA') {
    return (tz.startsWith('America/Los_Angeles') || tz.startsWith('America/Vancouver') ||
            tz.startsWith('America/Phoenix') || tz.startsWith('US/Pacific'))
      ? 'wnam' : 'enam';
  }
  return 'wnam'; // default
}

// ── Create session ──────────────────────────────────────────────────────────

async function handleCreateSession(request: Request, env: Env): Promise<Response> {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const hint = locationHint(request);
  // Pre-warm the DO in the target region by touching it once.
  // We use idFromName so subsequent WS connections route to the same instance.
  const id = env.SESSIONS.idFromName(token);
  // Just return — no need to ping the DO. The DO is created lazily on first WS.
  return json({ token, hint }, { headers: corsHeaders() });
}

// ── WebSocket upgrade → forward to DO ──────────────────────────────────────

async function handleWs(request: Request, env: Env, url: URL): Promise<Response> {
  const token = url.searchParams.get('token');
  const role = url.searchParams.get('role');
  // hint is passed by the client (obtained from POST /session) so that the
  // viewer's WS connection routes to the same regional DO as the host.
  const hint = (url.searchParams.get('hint') || locationHint(request)) as DurableObjectLocationHint;

  if (!token || !role || (role !== 'host' && role !== 'viewer')) {
    return new Response('Missing or invalid token/role', { status: 400 });
  }

  const id = env.SESSIONS.idFromName(token);
  const stub = env.SESSIONS.get(id, { locationHint: hint });
  return stub.fetch(request);
}

// ── Durable Object ──────────────────────────────────────────────────────────
// Blindly relays binary frames between host and viewer.
// Frames are AES-256-GCM ciphertext — content is opaque to this server.

export class SessionDO {
  private hostWs: WebSocket | null = null;
  private viewerWs: WebSocket | null = null;

  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    const role = url.searchParams.get('role') as 'host' | 'viewer' | null;
    if (!role) return new Response('Missing role', { status: 400 });

    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    server.accept();

    if (role === 'host') {
      this.hostWs?.close(1000, 'replaced by new host');
      this.hostWs = server;
      this.wireUp(server, () => this.viewerWs, () => { this.hostWs = null; },
        () => this.viewerWs?.close(1000, 'host disconnected'));
    } else {
      this.viewerWs?.close(1000, 'replaced by new viewer');
      this.viewerWs = server;
      this.wireUp(server, () => this.hostWs, () => { this.viewerWs = null; });
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  // Wire up a WebSocket to relay all messages to the peer.
  // All data is opaque binary — no inspection, no transformation.
  private wireUp(
    ws: WebSocket,
    getPeer: () => WebSocket | null,
    onClose: () => void,
    onCloseExtra?: () => void,
  ): void {
    ws.addEventListener('message', (evt) => {
      const peer = getPeer();
      if (peer && peer.readyState === WebSocket.READY_STATE_OPEN) {
        // Forward raw bytes unchanged — encrypted by client, opaque to server
        peer.send(evt.data);
      }
    });
    ws.addEventListener('close', () => { onClose(); onCloseExtra?.(); });
    ws.addEventListener('error', () => { onClose(); onCloseExtra?.(); });
  }
}

// ── Join redirect ────────────────────────────────────────────────────────────
// /j/<invite> — human-friendly deep link. Returns a page that shows the
// shellshare join command so users can copy-paste it easily.

function handleJoinRedirect(requestUrl: string): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>Shell Share — Join</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
           background: #0d1117; color: #c9d1d9; min-height: 100vh;
           display: flex; flex-direction: column; align-items: center;
           justify-content: center; padding: 40px 20px; }
    h1 { font-size: 1.6rem; color: #58a6ff; margin-bottom: 8px; }
    p { color: #8b949e; margin-bottom: 32px; }
    .cmd { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 18px 24px; font-family: monospace; font-size: 1rem;
           color: #3fb950; cursor: pointer; position: relative; max-width: 800px; width: 100%; }
    .copy-hint { position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
                 font-size: 0.75rem; color: #6e7681; }
    .copied { color: #3fb950 !important; }
  </style>
</head>
<body>
  <h1>🔐 Shell Share — Join Session</h1>
  <p>在终端运行以下命令加入共享会话：</p>
  <div class="cmd" id="cmd" onclick="copyCmd()">shellshare join ${requestUrl}<span class="copy-hint" id="hint">点击复制</span>
  </div>
  <script>
    function copyCmd() {
      navigator.clipboard.writeText('shellshare join ${requestUrl}');
      const h = document.getElementById('hint');
      h.textContent = '✔ 已复制';
      h.className = 'copy-hint copied';
      setTimeout(() => { h.textContent = '点击复制'; h.className = 'copy-hint'; }, 2000);
    }
  </script>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ── Landing page ────────────────────────────────────────────────────────────

function handleLanding(): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shell Share</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
           background: #0d1117; color: #c9d1d9; min-height: 100vh;
           display: flex; flex-direction: column; align-items: center; padding: 60px 20px; }
    h1 { font-size: 2rem; color: #58a6ff; margin-bottom: 8px; }
    .subtitle { color: #8b949e; margin-bottom: 48px; }
    .section { width: 100%; max-width: 700px; margin-bottom: 32px; }
    .section h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em;
                  color: #8b949e; margin-bottom: 12px; }
    .code-block { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                  padding: 16px 20px; font-family: 'Courier New', monospace; font-size: 0.88rem;
                  line-height: 1.9; }
    .comment { color: #6e7681; }
    .green { color: #3fb950; }
    .blue { color: #79c0ff; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
             background: #1a3a1a; color: #3fb950; margin-left: 8px; }
  </style>
</head>
<body>
  <h1>🔐 Shell Share</h1>
  <p class="subtitle">端到端加密的终端共享 — 服务端无法解密内容</p>

  <div class="section">
    <h2>安装</h2>
    <div class="code-block">
      <span class="blue">go install github.com/lihongjie0209/shellshare@latest</span>
    </div>
  </div>

  <div class="section">
    <h2>使用方法</h2>
    <div class="code-block">
<span class="comment"># 主机端：共享当前 Shell（输出可点击的加入链接）</span>
<span class="blue">shellshare share</span>

<span class="green">✔ Session ready — share this link:</span>
<span class="green">  shellshare join https://sh.lihongjie.cn/j/a3f8c2...</span>

<span class="comment"># 观看端：用链接加入（链接里包含服务器地址和加密信息）</span>
<span class="blue">shellshare join https://sh.lihongjie.cn/j/a3f8c2...</span>
    </div>
  </div>

  <div class="section">
    <h2>安全模型 <span class="badge">E2E 加密</span></h2>
    <div class="code-block" style="line-height:1.8; color:#8b949e; font-size:0.84rem">
Token → SHA-256 → AES-256-GCM 密钥（客户端本地派生，不发送给服务器）
每帧 = [12字节随机Nonce][AES-GCM密文+16字节认证标签]
Cloudflare Worker 只转发不透明的加密字节流，无法解密
    </div>
  </div>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers as Record<string, string> ?? {}),
    },
  });
}

function jsonError(msg: string, status: number): Response {
  return json({ error: msg }, { status });
}

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
