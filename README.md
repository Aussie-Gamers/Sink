# Discord login for Cloudflare Access (AussieGamers)

Lets staff sign in to Cloudflare Access-protected pages with their Discord account,
and lets Access policies check Discord roles in one or more servers.

Based on [Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker) (MIT).
Changes in this copy:

- All settings come from Worker secrets, not a `config.json` file, so it deploys from
  GitHub with Cloudflare's Git integration and no secrets ever sit in the repo.
- Missing or failed Discord responses return a clean 400 instead of crashing.
- A role lookup that fails for one server no longer breaks the login.
- `/health` shows whether the settings are present (never shows the values).
- `/admin` page: lists every Discord server the bot is in, each server's roles with
  copyable IDs, a per-server "Check roles" switch, the claim name to add in Zero Trust,
  an "Add bot to a server" link, and "Remove bot" per server. It must sit behind
  Cloudflare Access, and the Worker also verifies the Access token itself, so if Access
  isn't set up the page returns 403 rather than opening up.

## Settings

Worker > **Settings > Variables and Secrets** (the Runtime section, not Build), all type **Secret**:

| Name | Value |
|---|---|
| `DISCORD_CLIENT_ID` | Discord application ID |
| `DISCORD_CLIENT_SECRET` | Discord OAuth2 client secret |
| `DISCORD_TOKEN` | Discord bot token (for role checks) |
| `REDIRECT_URL` | `https://aussiegamers.cloudflareaccess.com/cdn-cgi/access/callback` |
| `ACCESS_TEAM_DOMAIN` | `https://aussiegamers.cloudflareaccess.com` |
| `ACCESS_AUD` | AUD tag of the Access app protecting `/admin` |
| `ROLE_SERVERS` | Optional starting list of server IDs, comma-separated. Once you save on `/admin`, the saved list is used instead. |

`wrangler.toml` holds only the KV namespace ID (not a secret).

## Cloudflare Access login method (OpenID Connect)

| Field | Value |
|---|---|
| App ID | Discord application ID |
| Client secret | Discord OAuth2 client secret |
| Auth URL | `https://discord-oidc.<subdomain>.workers.dev/authorize/guilds` |
| Token URL | `https://discord-oidc.<subdomain>.workers.dev/token` |
| Certificate URL | `https://discord-oidc.<subdomain>.workers.dev/jwks.json` |
| PKCE | On |
| OIDC claims | `id`, `preferred_username`, `name`, `guilds`, plus `roles:<server ID>` for each server in `ROLE_SERVERS` |

In a policy: **Include > OIDC Claims**, claim name `roles:<server ID>`, value `<role ID>`.

## Notes

- Never put this Worker behind Cloudflare Access; Access needs to reach it to log people in.
- Roles are read at sign-in. Removing someone's role takes effect when their Access session ends (session length is set on the policy).
- The Discord account must have a verified email address.
- The bot needs no permissions; it only needs to be a member of each server in `ROLE_SERVERS`.
