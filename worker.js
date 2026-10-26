// Discord login for Cloudflare Access (AussieGamers build).
// Based on Erisa/discord-oidc-worker (MIT). Changes:
//   - every setting comes from Worker secrets, not a config.json file, so it deploys
//     from GitHub with Cloudflare's Git integration and no secrets in the repo
//   - failed Discord responses return a clean 400 instead of crashing
//   - /health shows whether settings are present (never the values)
//   - /admin page (behind Cloudflare Access, checked again here) to see every server
//     the bot is in, their roles and IDs, switch role checks on/off per server, and
//     make the bot leave a server
//
// Runtime secrets (Worker > Settings > Variables and Secrets, Runtime section):
//   DISCORD_CLIENT_ID      Discord application ID
//   DISCORD_CLIENT_SECRET  Discord OAuth2 client secret
//   DISCORD_TOKEN          Discord bot token
//   REDIRECT_URL           https://<team>.cloudflareaccess.com/cdn-cgi/access/callback
//   ACCESS_TEAM_DOMAIN     https://<team>.cloudflareaccess.com   (for /admin)
//   ACCESS_AUD             AUD tag of the Access app that protects /admin
//   ROLE_SERVERS           optional starting list of server IDs (comma-separated);
//                          once you save on /admin, the saved list is used instead

import { Hono } from 'hono'
import * as jose from 'jose'

const DISCORD_API = 'https://discord.com/api/v10'
const ROLE_SERVERS_KEY = 'config:roleServers'

const algorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	hash: { name: 'SHA-256' },
}

const importAlgo = {
	name: 'RSASSA-PKCS1-v1_5',
	hash: { name: 'SHA-256' },
}

const isSnowflake = (s) => typeof s === 'string' && /^\d{15,22}$/.test(s)

function getConfig(env) {
	return {
		clientId: (env.DISCORD_CLIENT_ID || '').trim(),
		clientSecret: (env.DISCORD_CLIENT_SECRET || '').trim(),
		redirectURL: (env.REDIRECT_URL || '').trim(),
	}
}

// Servers to read roles from: the list saved on /admin, or ROLE_SERVERS until then.
async function getRoleServers(env) {
	const saved = await env.KV.get(ROLE_SERVERS_KEY, { type: 'json' })
	if (Array.isArray(saved)) return saved.filter(isSnowflake)
	return (env.ROLE_SERVERS || '').split(',').map(s => s.trim()).filter(isSnowflake)
}

async function loadOrGenerateKeyPair(KV) {
	let keyPair = {}
	let keyPairJson = await KV.get('keys', { type: 'json' })

	if (keyPairJson !== null) {
		keyPair.publicKey = await crypto.subtle.importKey('jwk', keyPairJson.publicKey, importAlgo, true, ['verify'])
		keyPair.privateKey = await crypto.subtle.importKey('jwk', keyPairJson.privateKey, importAlgo, true, ['sign'])

		return keyPair
	} else {
		keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

		await KV.put('keys', JSON.stringify({
			privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
			publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
		}))

		return keyPair
	}
}

function bot(env, path, init = {}) {
	return fetch(DISCORD_API + path, {
		...init,
		headers: { 'Authorization': 'Bot ' + env.DISCORD_TOKEN, ...(init.headers || {}) },
	})
}

const app = new Hono()

// ---------------------------------------------------------------- login flow

app.get('/health', async (c) => {
	const config = getConfig(c.env)
	const roleServers = c.env.KV ? await getRoleServers(c.env) : []
	return c.json({
		ok: Boolean(config.clientId && config.clientSecret && config.redirectURL && c.env.KV),
		roleServers: roleServers.length,
		botToken: Boolean(c.env.DISCORD_TOKEN),
		adminPage: Boolean(c.env.ACCESS_TEAM_DOMAIN && c.env.ACCESS_AUD),
	})
})

app.get('/authorize/:scopemode', async (c) => {
	const config = getConfig(c.env)

	if (!config.clientId
		|| c.req.query('client_id') !== config.clientId
		|| c.req.query('redirect_uri') !== config.redirectURL
		|| !c.req.query('state')
		|| !['guilds', 'email'].includes(c.req.param('scopemode'))) {
		return c.text('Bad request.', 400)
	}

	const params = new URLSearchParams({
		'client_id': config.clientId,
		'redirect_uri': config.redirectURL,
		'response_type': 'code',
		'scope': c.req.param('scopemode') == 'guilds' ? 'identify email guilds' : 'identify email',
		'state': c.req.query('state'),
		'prompt': 'none'
	}).toString()

	return c.redirect('https://discord.com/oauth2/authorize?' + params)
})

app.post('/token', async (c) => {
	const config = getConfig(c.env)
	const body = await c.req.parseBody()
	const code = body['code']

	if (!code || !config.clientId || !config.clientSecret) return c.text('Bad request.', 400)

	const params = new URLSearchParams({
		'client_id': config.clientId,
		'client_secret': config.clientSecret,
		'redirect_uri': config.redirectURL,
		'code': code,
		'grant_type': 'authorization_code',
		'scope': 'identify email'
	}).toString()

	const r = await fetch(DISCORD_API + '/oauth2/token', {
		method: 'POST',
		body: params,
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
	}).then(res => res.json()).catch(() => null)

	if (!r || !r['access_token']) return c.text('Bad request.', 400)

	const userInfo = await fetch(DISCORD_API + '/users/@me', {
		headers: { 'Authorization': 'Bearer ' + r['access_token'] }
	}).then(res => res.json()).catch(() => null)

	// Discord account must have a verified email address.
	if (!userInfo || !userInfo['id'] || !userInfo['verified']) return c.text('Bad request.', 400)

	let servers = []

	const serverResp = await fetch(DISCORD_API + '/users/@me/guilds', {
		headers: { 'Authorization': 'Bearer ' + r['access_token'] }
	})

	if (serverResp.status === 200) {
		const serverJson = await serverResp.json()
		servers = serverJson.map(item => item['id'])
	}

	let roleClaims = {}
	const roleServers = await getRoleServers(c.env)

	if (c.env.DISCORD_TOKEN && roleServers.length) {
		await Promise.all(roleServers.map(async guildId => {
			if (!servers.includes(guildId)) return

			const memberResp = await bot(c.env, `/guilds/${guildId}/members/${userInfo['id']}`)
			if (memberResp.status !== 200) return

			const memberJson = await memberResp.json()
			if (Array.isArray(memberJson.roles)) {
				roleClaims[`roles:${guildId}`] = memberJson.roles
			}
		}))
	}

	let preferred_username = userInfo['username']

	if (userInfo['discriminator'] && userInfo['discriminator'] !== '0') {
		preferred_username += `#${userInfo['discriminator']}`
	}

	const displayName = userInfo['global_name'] ?? userInfo['username']

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: config.clientId,
		preferred_username,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		global_name: userInfo['global_name'],
		name: displayName,
		guilds: servers
	})
		.setProtectedHeader({ alg: 'RS256', kid: 'jwtRS256' })
		.setExpirationTime('1h')
		.setAudience(config.clientId)
		.sign((await loadOrGenerateKeyPair(c.env.KV)).privateKey)

	return c.json({
		...r,
		scope: 'identify email',
		id_token: idToken
	})
})

app.get('/jwks.json', async (c) => {
	const publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey
	return c.json({
		keys: [{
			alg: 'RS256',
			kid: 'jwtRS256',
			...(await crypto.subtle.exportKey('jwk', publicKey))
		}]
	})
})

// ---------------------------------------------------------------- admin page
// Cloudflare Access must protect /admin. The Worker also checks the Access token
// itself, so a missing or misconfigured Access app fails closed (403), not open.

const jwksCache = new Map()

async function verifyAccess(c) {
	const team = (c.env.ACCESS_TEAM_DOMAIN || '').trim().replace(/\/+$/, '')
	const aud = (c.env.ACCESS_AUD || '').trim()
	const token = c.req.header('Cf-Access-Jwt-Assertion')
	if (!team.startsWith('https://') || !aud || !token) return null

	let jwks = jwksCache.get(team)
	if (!jwks) {
		jwks = jose.createRemoteJWKSet(new URL(team + '/cdn-cgi/access/certs'))
		jwksCache.set(team, jwks)
	}

	try {
		const { payload } = await jose.jwtVerify(token, jwks, { issuer: team, audience: aud })
		return payload
	} catch {
		return null
	}
}

app.use('/admin', adminGuard)
app.use('/admin/*', adminGuard)

async function adminGuard(c, next) {
	c.header('Cache-Control', 'no-store')
	c.header('X-Frame-Options', 'DENY')
	c.header('Referrer-Policy', 'no-referrer')

	const identity = await verifyAccess(c)
	if (!identity) return c.text('Forbidden.', 403)

	if (c.req.method !== 'GET') {
		// Block cross-site requests: same origin, plus a header a plain form can't send.
		const origin = c.req.header('Origin')
		if (origin !== new URL(c.req.url).origin || c.req.header('X-Admin') !== '1') {
			return c.text('Forbidden.', 403)
		}
	}

	c.set('identity', identity)
	await next()
}

app.get('/admin', (c) => {
	c.header('Content-Security-Policy',
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https://cdn.discordapp.com; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	return c.html(ADMIN_HTML)
})

app.get('/admin/api/state', async (c) => {
	if (!c.env.DISCORD_TOKEN) return c.json({ error: 'DISCORD_TOKEN is not set.' }, 500)

	const config = getConfig(c.env)
	const roleServers = await getRoleServers(c.env)

	const guildsResp = await bot(c.env, '/users/@me/guilds')
	if (guildsResp.status !== 200) {
		return c.json({ error: `Discord returned ${guildsResp.status} listing servers. Check the bot token.` }, 502)
	}
	const guilds = await guildsResp.json()

	const servers = await Promise.all(guilds.map(async g => {
		let roles = []
		const rolesResp = await bot(c.env, `/guilds/${g.id}/roles`)
		if (rolesResp.status === 200) {
			roles = (await rolesResp.json())
				.filter(r => r.id !== g.id) // drop @everyone
				.sort((a, b) => b.position - a.position)
				.map(r => ({ id: r.id, name: r.name, color: r.color, managed: r.managed }))
		}
		return {
			id: g.id,
			name: g.name,
			icon: g.icon ? `https://cdn.discordapp.com/icons/${g.id}/${g.icon}.png?size=64` : null,
			checkRoles: roleServers.includes(g.id),
			roles,
		}
	}))

	const inServer = new Set(guilds.map(g => g.id))

	return c.json({
		signedInAs: c.get('identity').email || null,
		servers,
		missing: roleServers.filter(id => !inServer.has(id)),
		inviteUrl: config.clientId
			? `https://discord.com/oauth2/authorize?client_id=${config.clientId}&scope=bot&permissions=0`
			: null,
	})
})

app.post('/admin/api/role-servers', async (c) => {
	const body = await c.req.json().catch(() => null)
	if (!body || !Array.isArray(body.ids) || body.ids.length > 50 || !body.ids.every(isSnowflake)) {
		return c.json({ error: 'Invalid list.' }, 400)
	}
	const ids = [...new Set(body.ids)]
	await c.env.KV.put(ROLE_SERVERS_KEY, JSON.stringify(ids))
	return c.json({ ok: true, ids })
})

app.post('/admin/api/leave', async (c) => {
	const body = await c.req.json().catch(() => null)
	if (!body || !isSnowflake(body.id)) return c.json({ error: 'Invalid server.' }, 400)

	const resp = await bot(c.env, `/users/@me/guilds/${body.id}`, { method: 'DELETE' })
	if (resp.status !== 204) return c.json({ error: `Discord returned ${resp.status}.` }, 502)

	const ids = (await getRoleServers(c.env)).filter(id => id !== body.id)
	await c.env.KV.put(ROLE_SERVERS_KEY, JSON.stringify(ids))
	return c.json({ ok: true })
})

const ADMIN_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Discord login servers</title>
<style>
  :root { --bg:#06070a; --card:#10131a; --line:#232836; --text:#e6e8ee; --muted:#9aa3b2; --teal:#5eead4; --rose:#fb7185; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width:880px; margin:0 auto; padding:24px 16px 64px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 20px; }
  .bar { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px; }
  button, a.btn { font:inherit; border:1px solid var(--line); background:var(--card); color:var(--text); border-radius:8px; padding:7px 12px; cursor:pointer; text-decoration:none; }
  button:hover, a.btn:hover { border-color:var(--teal); }
  button.primary { background:var(--teal); color:#04110f; border-color:var(--teal); font-weight:600; }
  button.danger { color:var(--rose); }
  button:disabled { opacity:.5; cursor:default; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:12px; }
  .head { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .head img, .head .ph { width:40px; height:40px; border-radius:50%; background:#1b2030; flex:none; }
  .name { font-weight:600; }
  .id { color:var(--muted); font:13px ui-monospace, Consolas, monospace; }
  .grow { flex:1; min-width:180px; }
  label.toggle { display:flex; align-items:center; gap:8px; cursor:pointer; }
  .claim { margin-top:10px; font:13px ui-monospace, Consolas, monospace; color:var(--teal); word-break:break-all; }
  details { margin-top:10px; }
  summary { cursor:pointer; color:var(--muted); }
  table { width:100%; border-collapse:collapse; margin-top:8px; font-size:14px; }
  td { padding:6px 4px; border-top:1px solid var(--line); vertical-align:middle; }
  td.idc { font:13px ui-monospace, Consolas, monospace; color:var(--muted); white-space:nowrap; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; vertical-align:middle; }
  .warn { border-color:#7c2d12; background:#1a0f0a; }
  .msg { min-height:22px; color:var(--teal); margin-bottom:12px; }
  .msg.err { color:var(--rose); }
  .small { font-size:13px; color:var(--muted); }
  button.copy { padding:2px 8px; font-size:12px; }
</style>
</head>
<body>
<main>
  <h1>Discord login servers</h1>
  <p class="sub" id="who">Loading…</p>
  <div class="bar">
    <button class="primary" id="save" disabled>Save role checks</button>
    <a class="btn" id="invite" target="_blank" rel="noopener" hidden>Add bot to a server</a>
    <button id="reload">Refresh</button>
  </div>
  <div class="msg" id="msg"></div>
  <div id="missing"></div>
  <div id="list"></div>
  <p class="small">Role checks on = people signing in get a <code>roles:&lt;server ID&gt;</code> claim for that server.
  Add the same claim name to the Discord login method in Zero Trust, then use it in policies
  (Include → OIDC Claims → claim name, role ID as the value).</p>
</main>
<script>
const $ = (s) => document.querySelector(s)
let state = null, dirty = false

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v)
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? '' : v)
  }
  for (const kid of kids.flat()) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)))
  return n
}

function say(text, err) { const m = $('#msg'); m.textContent = text || ''; m.className = 'msg' + (err ? ' err' : '') }

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin': '1' }, body: JSON.stringify(body)
  }
  const r = await fetch(path, opts)
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(data.error || ('Request failed (' + r.status + ')'))
  return data
}

function copyBtn(text) {
  return el('button', { class: 'copy', type: 'button', onclick: async (e) => {
    try { await navigator.clipboard.writeText(text); e.target.textContent = 'Copied' } catch { e.target.textContent = 'Copy failed' }
    setTimeout(() => (e.target.textContent = 'Copy'), 1500)
  } }, 'Copy')
}

function render() {
  $('#who').textContent = 'Signed in as ' + (state.signedInAs || 'unknown') + ' · bot is in ' + state.servers.length + ' server(s)'
  const inv = $('#invite')
  if (state.inviteUrl) { inv.href = state.inviteUrl; inv.hidden = false }

  const miss = $('#missing'); miss.replaceChildren()
  if (state.missing.length) {
    miss.append(el('div', { class: 'card warn' },
      el('div', { class: 'name' }, 'Role checks are on for servers the bot is not in'),
      el('div', { class: 'small' }, 'These IDs do nothing until the bot is added there: ' + state.missing.join(', '))))
  }

  const list = $('#list'); list.replaceChildren()
  if (!state.servers.length) list.append(el('div', { class: 'card' }, 'The bot is not in any servers yet.'))

  for (const s of state.servers) {
    const cb = el('input', { type: 'checkbox', checked: s.checkRoles, onchange: (e) => { s.checkRoles = e.target.checked; dirty = true; $('#save').disabled = false; render() } })
    const rows = s.roles.map(r => el('tr', {},
      el('td', {}, el('span', { class: 'dot', style: 'background:' + (r.color ? '#' + r.color.toString(16).padStart(6, '0') : '#4b5563') }), r.name, r.managed ? ' (bot role)' : ''),
      el('td', { class: 'idc' }, r.id),
      el('td', {}, copyBtn(r.id))))

    list.append(el('div', { class: 'card' },
      el('div', { class: 'head' },
        s.icon ? el('img', { src: s.icon, alt: '' }) : el('div', { class: 'ph' }),
        el('div', { class: 'grow' }, el('div', { class: 'name' }, s.name), el('div', { class: 'id' }, s.id, ' ', copyBtn(s.id))),
        el('label', { class: 'toggle' }, cb, 'Check roles'),
        el('button', { class: 'danger', type: 'button', onclick: () => leave(s) }, 'Remove bot')),
      s.checkRoles ? el('div', { class: 'claim' }, 'Claim name: roles:' + s.id, ' ', copyBtn('roles:' + s.id)) : null,
      el('details', {}, el('summary', {}, s.roles.length + ' roles'), el('table', {}, rows))))
  }
}

async function load() {
  say('Loading…')
  try { state = await api('/admin/api/state'); dirty = false; $('#save').disabled = true; render(); say('') }
  catch (e) { say(e.message, true) }
}

async function save() {
  const ids = state.servers.filter(s => s.checkRoles).map(s => s.id)
  $('#save').disabled = true
  try { await api('/admin/api/role-servers', { ids }); say('Saved. Applies to the next sign-in.'); await load() }
  catch (e) { say(e.message, true); $('#save').disabled = false }
}

async function leave(s) {
  if (!confirm('Remove the bot from "' + s.name + '"?\\n\\nRole-based access for that server stops working until the bot is added back.')) return
  try { await api('/admin/api/leave', { id: s.id }); say('Bot removed from ' + s.name + '.'); await load() }
  catch (e) { say(e.message, true) }
}

$('#save').addEventListener('click', save)
$('#reload').addEventListener('click', () => { if (!dirty || confirm('Discard unsaved changes?')) load() })
window.addEventListener('beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = '' } })
load()
</script>
</body>
</html>`

export default app
