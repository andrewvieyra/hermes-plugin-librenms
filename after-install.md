# LibreNMS plugin installed

The model reads LibreNMS freely and writes only through a plan a person approves. How far that holds
depends on five choices:

1. **A least-privilege token.** `LIBRENMS_TOKEN` carries every right of its LibreNMS user, and
   LibreNMS checks no per-token scope. Give the agent a dedicated user: the `global-read` role for
   `write_mode: read_only`, a custom role with only the permissions the enabled operations need for
   writes, never `admin`. On LibreNMS 26.9.0 or later, give the token an expiry when you create it
   (the default is never). If the token you entered above is an admin's or your own, replace it in
   this profile's `.env` (`~/.hermes/.env`, or `~/.hermes/profiles/<name>/.env`).
2. **`operator_only` where others or automation reach the agent.** On a gateway other people talk to,
   and on a profile that runs cron jobs, webhooks or the API server, set `write_mode: operator_only`
   under `plugins.entries.librenms.settings` in that profile's `config.yaml`: the model plans and a
   person applies with `/librenms apply <plan_id>`. `read_only` turns writes off altogether.
3. **Approval on.** Keep `require_approval: true` (the default), and no YOLO mode or
   `approvals.mode: off` on that profile, so every apply and rollback the model calls is shown to you
   first.
4. **No local shell for the model.** Put Hermes' terminal tool on a container or remote backend, or
   turn it off. On the local backend the model's commands see the token; the plugin refuses commands
   that read it by name and asks you before one reads `.env` or prints an environment holding it, but
   that is a heuristic, and the token's LibreNMS role is the limit that holds.
5. **Check it.** Enable the plugin if you did not above (`hermes plugins enable librenms`), start a
   new session and run `/librenms status`. Settle every warning and settings error it shows.

The rest (deletes and device adds, which stay off until you allow them, the audit log and its
forwarding, every setting) is in the plugin's README.md and SECURITY.md:
https://github.com/andrewvieyra/hermes-plugin-librenms
