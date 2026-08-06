// mb-shares worker: private gist-like over Workers KV.
// Viewers authenticate with Google (only verified @ALLOWED_DOMAIN accounts);
// the `share` CLI publishes with a bearer token. No public listing: `/` is
// blank except for ADMIN_EMAIL; share slugs carry a random suffix.
//
// ponytail: KV free tier (1GB total, 25MB/file, ~60s global propagation).
// Swap the SHARES binding to an R2 bucket if those ceilings ever bite.

import { marked } from 'marked'

const SESSION_DAYS = 7

export default {
  async fetch(req, env) {
    const url = new URL(req.url)

    // CLI endpoints: bearer token, no cookies involved.
    const bearer = (req.headers.get('authorization') || '').replace(/^Bearer /, '')
    const tokenOk = env.UPLOAD_TOKEN && bearer === env.UPLOAD_TOKEN
    if (req.method === 'PUT' || req.method === 'DELETE' || url.pathname === '/_list') {
      if (!tokenOk) return new Response('forbidden', { status: 403 })
      return cli(req, url, env)
    }

    if (url.pathname === '/auth/callback') return handleCallback(url, env)

    const email = await sessionEmail(req, env)
    if (!email) return redirectToGoogle(url, env)

    return serve(url, email, env)
  },
}

// ---------- KV helpers ----------

async function allKeys(env, prefix) {
  const names = []
  let cursor
  do {
    const l = await env.SHARES.list({ prefix, cursor })
    names.push(...l.keys.map((k) => k.name))
    cursor = l.list_complete ? undefined : l.cursor
  } while (cursor)
  return names
}

async function sharePrefixes(env) {
  const tops = new Set()
  for (const name of await allKeys(env)) tops.add(name.split('/')[0])
  return [...tops].sort()
}

// ---------- CLI (bearer token) ----------

async function cli(req, url, env) {
  if (url.pathname === '/_list') {
    const tops = await sharePrefixes(env)
    return new Response(tops.join('\n') + (tops.length ? '\n' : ''))
  }

  const key = decodeURIComponent(url.pathname.slice(1))
  if (!key) return new Response('missing key', { status: 400 })

  if (req.method === 'PUT') {
    await env.SHARES.put(key, await req.arrayBuffer())
    return new Response('ok\n')
  }

  // DELETE /name/ removes every object under the prefix
  const names = await allKeys(env, key)
  await Promise.all(names.map((n) => env.SHARES.delete(n)))
  return new Response(`deleted ${names.length}\n`)
}

// ---------- auth ----------

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function hmac(env, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  return b64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)))
}

async function sessionEmail(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)s=([^;]+)/)
  if (!m) return null
  const [emailB64, exp, sig] = m[1].split('.')
  if (!emailB64 || !exp || !sig) return null
  if (Number(exp) < Date.now() / 1000) return null
  const expected = await hmac(env, `${emailB64}.${exp}`)
  if (sig !== expected) return null
  return atob(emailB64.replace(/-/g, '+').replace(/_/g, '/'))
}

function redirectToGoogle(url, env) {
  const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth')
  auth.searchParams.set('client_id', env.GOOGLE_CLIENT_ID)
  auth.searchParams.set('redirect_uri', `${url.origin}/auth/callback`)
  auth.searchParams.set('response_type', 'code')
  auth.searchParams.set('scope', 'openid email')
  auth.searchParams.set('hd', env.ALLOWED_DOMAIN) // UI hint only; enforced in callback
  // state carries the original path so login lands back on the requested share
  auth.searchParams.set('state', btoa(url.pathname + url.search))
  return Response.redirect(auth.toString(), 302)
}

async function handleCallback(url, env) {
  const code = url.searchParams.get('code')
  if (!code) return new Response('missing code', { status: 400 })

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/callback`,
      grant_type: 'authorization_code',
    }),
  })
  const tok = await r.json()
  if (!tok.id_token) return new Response('auth failed', { status: 403 })

  // The id_token comes straight from Google's token endpoint over TLS in the
  // same request, so decoding without signature verification is sound here.
  const payload = JSON.parse(
    atob(tok.id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
  )
  const ok =
    payload.aud === env.GOOGLE_CLIENT_ID &&
    (payload.iss === 'https://accounts.google.com' || payload.iss === 'accounts.google.com') &&
    payload.email_verified &&
    payload.email?.toLowerCase().endsWith(`@${env.ALLOWED_DOMAIN}`)
  if (!ok) return new Response(`access limited to @${env.ALLOWED_DOMAIN} accounts`, { status: 403 })

  const emailB64 = b64url(new TextEncoder().encode(payload.email.toLowerCase()))
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400
  const sig = await hmac(env, `${emailB64}.${exp}`)

  let dest = '/'
  try { dest = atob(url.searchParams.get('state') || '') || '/' } catch {}
  // must be a same-origin absolute path: "//host" and "/\host" are
  // protocol-relative redirects in browsers -> open redirect
  if (!/^\/(?![/\\])/.test(dest)) dest = '/'

  return new Response(null, {
    status: 302,
    headers: {
      location: dest,
      'set-cookie':
        `s=${emailB64}.${exp}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`,
    },
  })
}

// ---------- serving ----------

const TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css', js: 'text/javascript',
  json: 'application/json', txt: 'text/plain; charset=utf-8',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
  pdf: 'application/pdf', csv: 'text/csv', mp4: 'video/mp4', wasm: 'application/wasm',
}

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))

function page(title, body) {
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
  body{max-width:52rem;margin:2rem auto;padding:0 1rem;font:16px/1.6 -apple-system,system-ui,sans-serif;color:#1f2328}
  /* pre breaks out of the 52rem prose column: as wide as its content needs,
     capped at the viewport, centered; overflow-x scrolls only past that */
  pre{background:#f6f8fa;padding:1rem;border-radius:6px;overflow-x:auto;
      box-sizing:border-box;width:fit-content;min-width:100%;
      max-width:calc(100vw - 2rem);position:relative;left:50%;transform:translateX(-50%)}
  code{background:#f6f8fa;padding:.15em .35em;border-radius:4px;font-size:.9em}
  pre code{background:none;padding:0}
  img{max-width:100%}
  a{color:#0969da}
  blockquote{border-left:4px solid #d1d9e0;margin-left:0;padding-left:1rem;color:#59636e}
  table{border-collapse:collapse}td,th{border:1px solid #d1d9e0;padding:.3em .7em}
  .anchor{opacity:0;margin-right:.35em;text-decoration:none}
  :hover>.anchor{opacity:1}
  :target{background:#fff8c5}
  @media (prefers-color-scheme: dark){
    body{background:#0d1117;color:#e6edf3}
    pre,code{background:#161b22}
    a{color:#4493f8}
    :target{background:#3a3000}
  }
</style>
${body}
<script>
(function () {
  var used = new Set(Array.from(document.querySelectorAll('[id]'), function (e) { return e.id }))
  function claim(want) {
    var id = want, n = 2
    while (used.has(id)) id = want + '.' + n++
    used.add(id)
    return id
  }
  function link(el, id) {
    el.id = id
    var a = document.createElement('a')
    a.href = '#' + id; a.textContent = '#'; a.className = 'anchor'
    el.prepend(a)
  }
  document.querySelectorAll('h1,h2,h3,h4,h5,h6').forEach(function (h) {
    link(h, h.id || claim(h.textContent.trim().toLowerCase().replace(/[^\\w]+/g, '-').replace(/^-|-$/g, '') || 'h'))
  })
  // ordered-list items: id encodes the numbering path, e.g. item-3-2 = 3.b
  document.querySelectorAll('ol > li').forEach(function (li) {
    var path = [], el = li
    while (el && el.tagName === 'LI' && el.parentElement.tagName === 'OL') {
      var ol = el.parentElement
      path.unshift((ol.start || 1) + Array.prototype.indexOf.call(ol.children, el))
      el = ol.parentElement.closest('li')
    }
    link(li, claim('item-' + path.join('-')))
  })
})()
</script>`,
    { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'private, no-cache' } },
  )
}

const notFound = () => page('not found', '<h1>404</h1>')

async function serve(url, email, env) {
  const key = decodeURIComponent(url.pathname.slice(1))

  if (key === '') {
    if (email !== env.ADMIN_EMAIL) {
      return page('mb-shares', '<h1>mb-shares</h1><p>Nothing here. If someone meant for you to see something, they sent you a direct link.</p>')
    }
    const items = (await sharePrefixes(env)).map(
      (p) => `<li><a href="/${esc(p)}/">${esc(p)}</a></li>`,
    )
    return page('shares', `<h1>shares (admin view)</h1><ul>${items.join('')}</ul>`)
  }

  if (key.endsWith('/')) {
    for (const cand of [`${key}index.md`, `${key}index.html`]) {
      const hit = await render(cand, env)
      if (hit) return hit
    }
    const names = await allKeys(env, key)
    if (!names.length) return notFound()
    const items = names.map(
      (n) => `<li><a href="/${esc(n)}">${esc(n.slice(key.length))}</a></li>`,
    )
    return page(key, `<h1>${esc(key.replace(/\/$/, ''))}</h1><ul>${items.join('')}</ul>`)
  }

  const hit = await render(key, env)
  if (hit) return hit

  // /name -> /name/ when the share exists
  const l = await env.SHARES.list({ prefix: `${key}/`, limit: 1 })
  if (l.keys.length) return Response.redirect(`${url.origin}/${key}/`, 302)
  return notFound()
}

// Grammar hints for the <pre> page. Unknown text extensions still render,
// just without a language class (hljs auto-detects among its common set).
// Values are highlight.js language names (also the CDN module filename).
const CODE_LANGS = {
  clj: 'clojure', cljs: 'clojure', cljc: 'clojure', edn: 'clojure', bb: 'clojure',
  py: 'python', rb: 'ruby', sh: 'bash', zsh: 'bash', bash: 'bash', sql: 'sql',
  yaml: 'yaml', yml: 'yaml', toml: 'ini', go: 'go', rs: 'rust',
  java: 'java', kt: 'kotlin', ts: 'typescript', tsx: 'typescript', jsx: 'javascript',
  c: 'c', h: 'c', cpp: 'cpp', diff: 'diff', patch: 'diff',
  gleam: 'rust', // no official hljs gleam grammar; rust keywords are close
  lis: 'rust', // Lisette: rust-like syntax, no hljs grammar of its own
}

const HLJS = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1'

// Returns a Response, or null when the key doesn't exist.
async function render(key, env) {
  const ext = key.split('.').pop().toLowerCase()
  if (ext === 'md') {
    const md = await env.SHARES.get(key, 'text')
    if (md === null) return null
    const title = (md.match(/^#\s+(.+)$/m) || [, key])[1]
    return page(title, marked.parse(md))
  }
  if (TYPES[ext]) {
    const body = await env.SHARES.get(key, 'stream')
    if (body === null) return null
    return new Response(body, {
      headers: { 'content-type': TYPES[ext], 'cache-control': 'private, no-cache' },
    })
  }

  // Unknown extension: text renders as a highlighted <pre> page; only
  // genuinely binary content (null byte early on) falls back to download.
  const buf = await env.SHARES.get(key, 'arrayBuffer')
  if (buf === null) return null
  if (new Uint8Array(buf, 0, Math.min(8192, buf.byteLength)).includes(0)) {
    return new Response(buf, {
      headers: { 'content-type': 'application/octet-stream', 'cache-control': 'private, no-cache' },
    })
  }
  const lang = CODE_LANGS[ext]
  return page(
    key.split('/').pop(),
    `<link rel="stylesheet" media="(prefers-color-scheme: light)" href="${HLJS}/styles/github.min.css">
<link rel="stylesheet" media="(prefers-color-scheme: dark)" href="${HLJS}/styles/github-dark.min.css">
<pre><code${lang ? ` class="language-${lang}"` : ''}>${esc(new TextDecoder().decode(buf))}</code></pre>
<script src="${HLJS}/highlight.min.js"></script>
${lang ? `<script src="${HLJS}/languages/${lang}.min.js"></script>` : ''}
<script>hljs.highlightAll()</script>`,
  )
}
