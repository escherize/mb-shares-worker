// mb-shares worker: private gist-like over Workers KV.
// Viewers authenticate with Google (only verified @ALLOWED_DOMAIN accounts);
// the `share` CLI publishes with a bearer token. Every user gets their own
// token (minted at /_token) and sees only their own shares at `/`;
// ADMIN_EMAIL sees everything. Share slugs carry a random suffix.
//
// ponytail: KV free tier (1GB total, 25MB/file, ~60s global propagation).
// Swap the SHARES binding to an R2 bucket if those ceilings ever bite.

import { marked } from 'marked'
import { zipSync } from 'fflate'
import CLI_SH from '../bin/share' // text module (wrangler.toml rules), served at /_cli

const SESSION_DAYS = 7

export default {
  async fetch(req, env) {
    const url = new URL(req.url)

    // CLI endpoints: bearer token, no cookies involved. Bearer GET serves
    // raw bytes (for `share download`); browsers never send one.
    const bearer = (req.headers.get('authorization') || '').replace(/^Bearer /, '')
    if (req.method === 'PUT' || req.method === 'DELETE' || url.pathname === '/_list'
        || (req.method === 'GET' && bearer)) {
      const who = await tokenEmail(env, bearer)
      if (!who) return new Response('forbidden', { status: 403 })
      return cli(req, url, env, who)
    }

    if (url.pathname === '/auth/callback') return handleCallback(url, env)

    const email = await sessionEmail(req, env)
    if (!email) return redirectToGoogle(url, env)

    return serve(url, email, env, req.headers.get('accept'))
  },
}

// ---------- KV helpers ----------

async function allEntries(env, prefix) {
  const out = []
  let cursor
  do {
    const l = await env.SHARES.list({ prefix, cursor })
    out.push(...l.keys)
    cursor = l.list_complete ? undefined : l.cursor
  } while (cursor)
  return out
}

async function allKeys(env, prefix) {
  return (await allEntries(env, prefix)).map((k) => k.name)
}

// top-level slugs -> { n: file count, t: newest timestamp, o: owner email }.
// Files published before multi-user carry no owner; callers treat a missing
// o as ADMIN_EMAIL. Skips the _own/ bookkeeping keys.
async function shareTops(env) {
  const tops = new Map()
  for (const k of await allEntries(env)) {
    if (k.name.startsWith('_own/')) continue
    const top = k.name.split('/')[0]
    const s = tops.get(top) || { n: 0, t: 0, o: undefined }
    s.n += 1
    s.t = Math.max(s.t, k.metadata?.t || 0)
    s.o = s.o || k.metadata?.o
    tops.set(top, s)
  }
  return tops
}

// ---------- CLI (bearer token) ----------

async function cli(req, url, env, who) {
  const admin = who === env.ADMIN_EMAIL

  // the share script itself, for one-line install from the /_token page
  if (url.pathname === '/_cli') return new Response(CLI_SH)

  if (url.pathname === '/_list') {
    // ?prefix=slug/ lists every file in a share (any token -- download works
    // on anything you can view); bare _list lists your own share slugs
    const prefix = url.searchParams.get('prefix')
    const names = prefix
      ? await allKeys(env, prefix)
      : [...await shareTops(env)]
          .filter(([, s]) => admin || (s.o || env.ADMIN_EMAIL) === who)
          .map(([top]) => top).sort()
    return new Response(names.join('\n') + (names.length ? '\n' : ''))
  }

  const key = decodeURIComponent(url.pathname.slice(1))
  if (!key) return new Response('missing key', { status: 400 })

  if (req.method === 'GET') {
    const body = await env.SHARES.get(key, 'stream')
    if (body === null) return new Response('not found', { status: 404 })
    return new Response(body)
  }

  // Writes only touch your own shares (admin can touch anything). Owner
  // lives in a dedicated _own/<slug> key: a KV *read* per PUT instead of a
  // list -- the free tier allows 1k lists/day but 100k reads. A missing
  // _own key means the slug is unclaimed (every existing share got one
  // backfilled); the first PUT claims it. Racers on the same fresh slug are
  // moot: random suffixes.
  const top = key.replace(/\/.*$/, '')
  const ownKey = `_own/${top}`
  const owner = await env.SHARES.get(ownKey)

  if (owner && owner !== who && !admin) {
    return new Response(`owned by ${owner}\n`, { status: 403 })
  }

  if (req.method === 'PUT') {
    if (!owner) await env.SHARES.put(ownKey, who)
    // timestamp feeds the listing's newest-first sort; o shows in admin view
    await env.SHARES.put(key, await req.arrayBuffer(), { metadata: { t: Date.now(), o: who } })
    return new Response('ok\n')
  }

  // DELETE /name/ removes every object under the prefix
  const names = await allKeys(env, key)
  await Promise.all(names.map((n) => env.SHARES.delete(n)))
  await env.SHARES.delete(ownKey)
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

// Personal CLI tokens are stateless: t.<emailB64>.<hmac("tok."+emailB64)>.
// Verification recomputes the hmac -- nothing stored, nothing to revoke short
// of rotating SESSION_SECRET. The "tok." prefix keeps tokens and session
// cookies from doubling as each other despite the shared secret. The legacy
// shared UPLOAD_TOKEN still works and acts as ADMIN_EMAIL.
async function tokenEmail(env, bearer) {
  if (!bearer) return null
  if (env.UPLOAD_TOKEN && bearer === env.UPLOAD_TOKEN) return env.ADMIN_EMAIL
  const [tag, emailB64, sig] = bearer.split('.')
  if (tag !== 't' || !emailB64 || !sig) return null
  if (sig !== await hmac(env, `tok.${emailB64}`)) return null
  try { return atob(emailB64.replace(/-/g, '+').replace(/_/g, '/')) } catch { return null }
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
  jsonl: 'application/x-ndjson', ndjson: 'application/x-ndjson',
}

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))

// content fingerprint for the auto-refresh poll; djb2 is plenty for
// "did it change" and keeps page() synchronous
function vhash(s) {
  let h = 5381
  for (let i = 0; i < s.length; i++) h = (h * 33 + s.charCodeAt(i)) >>> 0
  return h.toString(36)
}

// opts.vsrc: what the auto-refresh fingerprint hashes; defaults to the body.
// Pages with time-relative text pass stable data instead to avoid a
// fingerprint that changes every render (= infinite reload loop).
// opts.copy: show the fixed top-right button that copies the raw file.
// opts.poll: false disables the auto-refresh poll -- the listing page must
// not re-render itself every 15s (each render costs a KV list; 1k/day cap).
function page(title, body, opts = {}) {
  const v = vhash(opts.vsrc || body)
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<meta name="v" content="${v}">
<script>try{var _t=localStorage.getItem('theme');if(_t)document.documentElement.setAttribute('data-theme',_t)}catch(e){}</script>
<style>
  :root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--link:#0969da;--border:#d1d9e0;
    --code-bg:#f6f8fa;--acc1:#953800;--acc2:#1a7f37;--target:#fff8c5}
  @media (prefers-color-scheme: dark){:root:not([data-theme=light]){--bg:#0d1117;--fg:#e6edf3;
    --muted:#8b949e;--link:#4493f8;--border:#30363d;--code-bg:#161b22;
    --acc1:#ffa657;--acc2:#7ee787;--target:#3a3000}}
  :root[data-theme=dark]{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--link:#4493f8;
    --border:#30363d;--code-bg:#161b22;--acc1:#ffa657;--acc2:#7ee787;--target:#3a3000}
  :root[data-theme=tokyo]{--bg:#1a1b26;--fg:#c0caf5;--muted:#565f89;--link:#7aa2f7;
    --border:#292e42;--code-bg:#16161e;--acc1:#ff9e64;--acc2:#9ece6a;--target:#33301f}
  :root[data-theme=nord]{--bg:#2e3440;--fg:#d8dee9;--muted:#8492ab;--link:#88c0d0;
    --border:#3b4252;--code-bg:#3b4252;--acc1:#d08770;--acc2:#a3be8c;--target:#4c566a}
  body{max-width:52rem;margin:2rem auto;padding:0 1rem;font:16px/1.6 -apple-system,system-ui,sans-serif;
    background:var(--bg);color:var(--fg)}
  /* pre/table break out of the 52rem prose column: as wide as content needs,
     capped at the viewport, centered; overflow-x scrolls only past that */
  pre,table{background:var(--code-bg);padding:1rem;border-radius:6px;overflow-x:auto;
      box-sizing:border-box;width:fit-content;min-width:100%;
      max-width:calc(100vw - 2rem);position:relative;left:50%;transform:translateX(-50%)}
  table{display:block;background:none;padding:0}
  button.copy{display:block;margin:0 0 .25rem auto;font:inherit;font-size:.75rem;
      color:var(--muted);background:none;border:1px solid var(--border);border-radius:6px;
      padding:.1em .6em;cursor:pointer}
  button.copy:hover{color:var(--fg);border-color:var(--muted)}
  code{background:var(--code-bg);padding:.15em .35em;border-radius:4px;font-size:.9em}
  pre code{background:none;padding:0}
  img{max-width:100%}
  a{color:var(--link)}
  blockquote{border-left:4px solid var(--border);margin-left:0;padding-left:1rem;color:var(--muted)}
  small{color:var(--muted)}
  table{border-collapse:collapse}td,th{border:1px solid var(--border);padding:.3em .7em}
  .anchor{opacity:0;margin-right:.35em;text-decoration:none}
  :hover>.anchor{opacity:1}
  :target{background:var(--target)}
  #cpall{position:fixed;top:.75rem;right:.75rem;z-index:9;font:inherit;font-size:.75rem;
    color:var(--muted);background:var(--code-bg);border:1px solid var(--border);
    border-radius:6px;padding:.15em .6em;cursor:pointer}
  #cpall:hover{color:var(--fg);border-color:var(--muted)}
  #thg{position:fixed;bottom:.75rem;right:.75rem;z-index:9;font:inherit;font-size:.75rem;
    color:var(--muted);background:var(--code-bg);border:1px solid var(--border);
    border-radius:6px;padding:.1em .3em}
</style>
<link rel="stylesheet" data-hl media="(prefers-color-scheme: light)" href="${HLJS}/styles/github.min.css">
<link rel="stylesheet" data-hl media="(prefers-color-scheme: dark)" href="${HLJS}/styles/github-dark.min.css">
${opts.copy ? '<button id="cpall" title="copy raw file contents">copy</button>' : ''}
${body}
<script src="${HLJS}/highlight.min.js"></script>
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
  document.querySelectorAll('pre').forEach(function (pre) {
    if (pre.closest('#pv')) return
    var b = document.createElement('button')
    b.textContent = 'copy'; b.className = 'copy'
    b.onclick = function () {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        b.textContent = 'copied'
        setTimeout(function () { b.textContent = 'copy' }, 1200)
      })
    }
    pre.insertAdjacentElement('beforebegin', b)
  })
  // explicit theme replaces the auto (media-query) hljs stylesheets
  var THL = { light: 'github', dark: 'github-dark', tokyo: 'tokyo-night-dark', nord: 'nord' }
  var tname = ''
  try { tname = localStorage.getItem('theme') || '' } catch (e) {}
  if (THL[tname]) {
    document.querySelectorAll('link[data-hl]').forEach(function (l) { l.remove() })
    var hlink = document.createElement('link')
    hlink.rel = 'stylesheet'
    hlink.href = '${HLJS}/styles/' + THL[tname] + '.min.css'
    document.head.appendChild(hlink)
  }
  // highlight: load grammars for declared fence languages (clojure always,
  // for auto-detecting unlabeled blocks - it is not in the common build)
  var ALIAS = ${JSON.stringify(CODE_LANGS)}
  var need = { clojure: true }
  document.querySelectorAll('code[class*="language-"]').forEach(function (c) {
    var m = c.className.match(/language-([\\w-]+)/)
    if (m) need[ALIAS[m[1]] || m[1]] = true
  })
  var pending = 0
  function done() { if (--pending === 0) hljs.highlightAll() }
  Object.keys(need).forEach(function (l) {
    if (hljs.getLanguage(l)) return
    pending++
    var s = document.createElement('script')
    s.src = '${HLJS}/languages/' + l + '.min.js'
    s.onload = s.onerror = done
    document.head.appendChild(s)
  })
  if (!pending) hljs.highlightAll()
  // theme picker: fixed bottom-right on every rendered page
  var tsel = document.createElement('select')
  tsel.id = 'thg'; tsel.title = 'theme'
  ;['auto', 'light', 'dark', 'tokyo', 'nord'].forEach(function (o) {
    var op = document.createElement('option')
    op.value = o === 'auto' ? '' : o
    op.textContent = o
    tsel.appendChild(op)
  })
  tsel.value = tname
  tsel.addEventListener('change', function () {
    try { localStorage.setItem('theme', tsel.value) } catch (e) {}
    location.reload()
  })
  document.body.appendChild(tsel)
  // top-right copy: fetch() gets raw bytes via Accept negotiation, so this
  // copies the true file content even on pretty-rendered pages
  var cp = document.getElementById('cpall')
  if (cp) cp.addEventListener('click', function () {
    fetch(location.href, { cache: 'no-store' })
      .then(function (r) { return r.text() })
      .then(function (t) { return navigator.clipboard.writeText(t) })
      .then(function () {
        cp.textContent = 'copied'; setTimeout(function () { cp.textContent = 'copy' }, 1200)
      })
      .catch(function () {})
  })
  // auto-refresh: reload when a push changes the content fingerprint
  ${opts.poll === false ? '' : `setInterval(function () {
    fetch(location.href, { cache: 'no-store' })
      .then(function (r) { return r.text() })
      .then(function (t) {
        var m = t.match(/name="v" content="([^"]+)"/)
        if (m && m[1] !== '${v}') location.reload()
      })
      .catch(function () {})
  }, 15000)`}
})()
</script>`,
    { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'private, no-cache' } },
  )
}

const notFound = () => page('not found', '<h1>404</h1>')

function ago(t) {
  if (!t) return '—'
  const m = Math.floor((Date.now() - t) / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}min ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}hr ${m % 60}min ago`
  const d = Math.floor(h / 24)
  if (d < 7) return `${d}d ${h % 24}hr ago`
  return new Date(t).toISOString().slice(0, 10)
}

async function serve(url, email, env, accept) {
  const key = decodeURIComponent(url.pathname.slice(1))

  if (key === '') {
    const admin = email === env.ADMIN_EMAIL
    // you see your shares; admin sees everyone's (with an owner column)
    const mine = [...await shareTops(env)]
      .filter(([, s]) => admin || (s.o || env.ADMIN_EMAIL) === email)
    // newest first; pre-timestamp shares (no metadata) sink to the bottom
    const sorted = mine.sort((a, b) => b[1].t - a[1].t || a[0].localeCompare(b[0]))
    const rows = sorted.map(([p, s]) =>
      `<tr><td class="s"><a href="/${esc(p)}/">${esc(p)}</a></td>${
        admin ? `<td class="o">${esc((s.o || env.ADMIN_EMAIL).split('@')[0])}</td>` : ''
      }<td class="n">${s.n} file${
        s.n === 1 ? '' : 's'}</td><td class="t" title="${
        s.t ? new Date(s.t).toISOString() : 'published before timestamps existed'}">${
        ago(s.t)}</td><td><button data-u="/${esc(p)}/">url</button></td></tr>`)
    return page('shares', `<style>
  .hd h1{margin:0 0 .5rem;font-size:1.3rem}
  #q{width:100%;box-sizing:border-box;font:inherit;font-size:.9rem;padding:.35em .6em;
    background:var(--code-bg);color:var(--fg);border:1px solid var(--border);
    border-radius:6px;margin:0 0 .75rem}
  #q:focus{outline:2px solid var(--link);outline-offset:-1px}
  table.lst{display:table;width:100%;min-width:0;max-width:none;left:auto;transform:none;
    background:none;padding:0;font-size:.9rem}
  .lst td{border:0;border-bottom:1px solid var(--border);padding:.3em .4em;white-space:nowrap}
  .lst td.s{width:100%;white-space:normal}
  .lst td.s a{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem;
    text-decoration:none}
  .lst td.s a:hover{text-decoration:underline}
  .lst td.o{color:var(--muted)}
  .lst td.n{color:var(--acc1);text-align:right}
  .lst td.t{color:var(--acc2)}
  .lst button{font:inherit;font-size:.7rem;color:var(--muted);background:none;
    border:1px solid var(--border);border-radius:5px;padding:.05em .45em;cursor:pointer}
  .lst button:hover{color:var(--fg);border-color:var(--muted)}
  #pv{display:none;position:fixed;z-index:10;max-width:44rem;max-height:45vh;overflow:hidden;
    background:var(--code-bg);border:1px solid var(--border);border-radius:6px;
    box-shadow:0 4px 16px rgba(0,0,0,.25);padding:.5rem .75rem}
  /* invisible bridges above/below: crossing the row->card gap stays "inside" */
  #pv::before{content:'';position:absolute;left:0;right:0;top:-14px;height:14px}
  #pv::after{content:'';position:absolute;left:0;right:0;bottom:-14px;height:14px}
  #pv .f{color:var(--muted);font-size:.75rem;margin:0 3.5rem .25rem 0;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  #pv .c{position:absolute;top:.35rem;right:.4rem;font:inherit;font-size:.7rem;
    color:var(--muted);background:none;border:1px solid var(--border);border-radius:5px;
    padding:.05em .45em;cursor:pointer}
  #pv .c:hover{color:var(--fg);border-color:var(--muted)}
  #pv pre{margin:0;padding:0;background:none;min-width:0;width:auto;left:0;transform:none;
    max-width:none;font-size:.75rem;line-height:1.4;white-space:pre-wrap;overflow:hidden}
</style>
<div class="hd"><h1>shares</h1></div>
<input id="q" placeholder="filter" autofocus>
<table class="lst"><tbody id="shares">${rows.join('')}</tbody></table>
${rows.length ? '' : '<p>No shares yet.</p>'}
<p><small><a href="/_token">cli setup</a></small></p>
<script>
document.getElementById('q').addEventListener('input', function () {
  var q = this.value.toLowerCase()
  document.querySelectorAll('#shares tr').forEach(function (tr) {
    tr.style.display = tr.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : ''
  })
})
document.querySelectorAll('.lst button').forEach(function (b) {
  b.addEventListener('click', function () {
    navigator.clipboard.writeText(location.origin + b.getAttribute('data-u')).then(function () {
      b.textContent = 'ok'; setTimeout(function () { b.textContent = 'url' }, 900)
    })
  })
})
var pv = document.createElement('div')
pv.id = 'pv'
pv.innerHTML = '<div class="f"></div><button class="c">copy</button><pre></pre>'
document.body.appendChild(pv)
var pvCache = {}, pvHide = null, pvCur = null
function hidePv() { pv.style.display = 'none'; pvCur = null }
function peek(u) {
  return pvCache[u]
    ? Promise.resolve(pvCache[u])
    : fetch(u + '_peek').then(function (r) { return r.json() })
        .then(function (j) { pvCache[u] = j; return j })
}
pv.addEventListener('mouseenter', function () { clearTimeout(pvHide) })
pv.addEventListener('mouseleave', function () { pvHide = setTimeout(hidePv, 150) })
pv.querySelector('.c').addEventListener('click', function () {
  var b = this
  fetch(pv.dataset.u, { cache: 'no-store' })
    .then(function (r) { return r.text() })
    .then(function (t) { return navigator.clipboard.writeText(t) })
    .then(function () {
      b.textContent = 'copied'; setTimeout(function () { b.textContent = 'copy' }, 1000)
    })
    .catch(function () {})
})
document.querySelectorAll('#shares tr').forEach(function (tr) {
  var a = tr.querySelector('td.s a')
  if (!a) return
  var u = a.getAttribute('href')
  tr.addEventListener('mouseenter', function () {
    clearTimeout(pvHide)
    pvCur = u
    peek(u).then(function (j) {
      if (pvCur !== u) return
      pv.querySelector('.f').textContent = j.file
      pv.querySelector('pre').textContent = j.text
      pv.dataset.u = u + j.file
      var r = tr.getBoundingClientRect()
      pv.style.left = Math.min(r.left + 24, innerWidth - 400) + 'px'
      pv.style.display = 'block'
      var below = innerHeight - r.bottom - 8
      if (below < pv.offsetHeight && r.top > innerHeight / 2) {
        pv.style.top = Math.max(4, r.top - pv.offsetHeight - 4) + 'px'
      } else {
        pv.style.top = (r.bottom + 4) + 'px'
      }
    }).catch(function () {})
  })
  tr.addEventListener('mouseleave', function () {
    pvHide = setTimeout(hidePv, 150)
  })
})
// warm the peek cache so hovers are instant (4 in flight at a time)
var pvq = Array.prototype.map.call(
  document.querySelectorAll('#shares td.s a'),
  function (a) { return a.getAttribute('href') })
var pvActive = 0
function pvPump() {
  while (pvq.length && pvActive < 4) {
    (function (u) {
      pvActive++
      peek(u).catch(function () {}).then(function () { pvActive--; pvPump() })
    })(pvq.shift())
  }
}
pvPump()
</script>`, { vsrc: JSON.stringify(sorted), poll: false })
  }

  // /_token: personal CLI token + setup, derived from the signed-in session
  if (key === '_token') {
    const emailB64 = b64url(new TextEncoder().encode(email))
    const token = `t.${emailB64}.${await hmac(env, `tok.${emailB64}`)}`
    const conf = `mkdir -p ~/.config/mb-shares
cat > ~/.config/mb-shares/env <<'EOF'
BASE_URL=${url.origin}
UPLOAD_TOKEN=${token}
EOF`
    const install = `curl -sH "Authorization: Bearer ${token}" ${url.origin}/_cli -o ~/bin/share && chmod +x ~/bin/share`
    return page('cli setup', `<h1>cli setup</h1>
<p>Personal upload token for <code>${esc(email)}</code>. Save the config:</p>
<pre><code>${esc(conf)}</code></pre>
<p>Install the <code>share</code> script (needs <code>~/bin</code> on your PATH):</p>
<pre><code>${esc(install)}</code></pre>
<p>Then publish anything: <code>share thing.md</code> prints a URL. <code>share -h</code> for the rest.</p>`)
  }

  // /slug/_peek: first lines of the share's main file, for hover previews
  if (key.endsWith('/_peek')) {
    const prefix = key.slice(0, -'_peek'.length)
    const names = await allKeys(env, prefix)
    if (!names.length) return notFound()
    const pick = names.find((n) => n.endsWith('/index.md')) || names[0]
    const buf = await env.SHARES.get(pick, 'arrayBuffer')
    let text
    if (buf && !new Uint8Array(buf, 0, Math.min(4096, buf.byteLength)).includes(0)) {
      text = new TextDecoder().decode(buf.slice(0, 8192)).split('\n').slice(0, 10)
        .map((l) => (l.length > 160 ? l.slice(0, 160) + '…' : l)).join('\n')
    } else {
      text = names.map((n) => n.slice(prefix.length)).slice(0, 10).join('\n')
    }
    return new Response(JSON.stringify({ file: pick.slice(prefix.length), text }), {
      headers: { 'content-type': 'application/json', 'cache-control': 'private, no-cache' },
    })
  }

  // /slug/_zip: whole share as a zip (in-memory; KV caps files at 25MB)
  if (key.endsWith('/_zip')) {
    const prefix = key.slice(0, -'_zip'.length)
    const names = await allKeys(env, prefix)
    if (!names.length) return notFound()
    const files = {}
    for (const n of names) {
      files[n.slice(prefix.length)] = new Uint8Array(await env.SHARES.get(n, 'arrayBuffer'))
    }
    const base = prefix.replace(/\/$/, '').split('/').pop()
    return new Response(zipSync(files), {
      headers: {
        'content-type': 'application/zip',
        'content-disposition': `attachment; filename="${base}.zip"`,
        'cache-control': 'private, no-cache',
      },
    })
  }

  if (key.endsWith('/')) {
    for (const cand of [`${key}index.md`, `${key}index.html`]) {
      const hit = await render(cand, env, accept)
      if (hit) return hit
    }
    const names = await allKeys(env, key)
    if (!names.length) return notFound()
    // one file -> skip the listing, land on the file itself
    if (names.length === 1) return Response.redirect(`${url.origin}/${encodeURI(names[0])}`, 302)
    const items = names.map(
      (n) => `<li><a href="/${esc(n)}">${esc(n.slice(key.length))}</a></li>`,
    )
    return page(key, `<h1>${esc(key.replace(/\/$/, ''))}</h1><ul>${items.join('')}</ul>
<p><a href="/${esc(key)}_zip">download all (.zip)</a></p>`)
  }

  const hit = await render(key, env, accept)
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

function codePage(key, text, lang) {
  // page() carries hljs for all rendered pages; the class is enough
  return page(
    key.split('/').pop(),
    `<pre><code${lang ? ` class="language-${lang}"` : ''}>${esc(text)}</code></pre>`,
    { copy: true },
  )
}

// Reformat json/jsonl for display; malformed input passes through untouched.
function prettyJson(text, ext) {
  try {
    if (ext === 'json') return JSON.stringify(JSON.parse(text), null, 2)
    return text.trim().split('\n')
      .map((l) => JSON.stringify(JSON.parse(l), null, 2)).join('\n\n')
  } catch { return text }
}

// Minimal CSV parser: quoted fields, "" escapes, CRLF. No streaming (KV
// values cap at 25MB; csvPage slices input before parsing anyway).
function csvCells(text) {
  const rows = [[]]
  let cell = '', q = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++ } else q = false }
      else cell += c
    } else if (c === '"') q = true
    else if (c === ',') { rows.at(-1).push(cell); cell = '' }
    else if (c === '\n') { rows.at(-1).push(cell.replace(/\r$/, '')); cell = ''; rows.push([]) }
    else cell += c
  }
  rows.at(-1).push(cell)
  if (rows.at(-1).length === 1 && rows.at(-1)[0] === '') rows.pop()
  return rows
}

const MAX_CSV_ROWS = 1000

function csvPage(key, text) {
  const clipped = text.length > 2_000_000
  const rows = csvCells(clipped ? text.slice(0, 2_000_000).replace(/\n[^\n]*$/, '') : text)
  const tr = (cells, tag) => `<tr>${cells.map((c) => `<${tag}>${esc(c)}</${tag}>`).join('')}</tr>`
  const shown = rows.slice(1, MAX_CSV_ROWS + 1)
  const note = clipped || rows.length - 1 > shown.length
    ? `<p>showing first ${shown.length} rows — fetch the file directly (curl/wget) for all of it</p>` : ''
  return page(
    key.split('/').pop(),
    `<table><thead>${tr(rows[0] || [], 'th')}</thead><tbody>${shown.map((r) => tr(r, 'td')).join('')}</tbody></table>${note}`,
    { copy: true },
  )
}

// Returns a Response, or null when the key doesn't exist.
async function render(key, env, accept) {
  const ext = key.split('.').pop().toLowerCase()
  // browsers navigating (Accept: text/html) get pretty views; fetch()/curl
  // keep getting raw bytes so html shares can load their own data files
  const wantsHtml = /text\/html/.test(accept || '')

  if (ext === 'md') {
    const md = await env.SHARES.get(key, 'text')
    if (md === null) return null
    if (!wantsHtml) {
      return new Response(md, {
        headers: { 'content-type': 'text/markdown; charset=utf-8', 'cache-control': 'private, no-cache' },
      })
    }
    const title = (md.match(/^#\s+(.+)$/m) || [, key])[1]
    return page(title, marked.parse(md), { copy: true })
  }

  if (wantsHtml && ['json', 'jsonl', 'ndjson', 'csv'].includes(ext)) {
    const text = await env.SHARES.get(key, 'text')
    if (text === null) return null
    if (ext === 'csv') return csvPage(key, text)
    return codePage(key, prettyJson(text, ext), 'json')
  }

  if (TYPES[ext]) {
    const body = await env.SHARES.get(key, 'stream')
    if (body === null) return null
    return new Response(body, {
      headers: { 'content-type': TYPES[ext], 'cache-control': 'private, no-cache' },
    })
  }

  // Unknown extension: text renders as a highlighted <pre> page; binary
  // content (null byte early on) and non-browser requests get raw bytes.
  const buf = await env.SHARES.get(key, 'arrayBuffer')
  if (buf === null) return null
  const binary = new Uint8Array(buf, 0, Math.min(8192, buf.byteLength)).includes(0)
  if (binary || !wantsHtml) {
    return new Response(buf, {
      headers: { 'content-type': 'application/octet-stream', 'cache-control': 'private, no-cache' },
    })
  }
  return codePage(key, new TextDecoder().decode(buf), CODE_LANGS[ext])
}
