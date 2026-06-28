# Installing NetCopilot — a step-by-step guide

This guide takes you from a fresh computer to a **running NetCopilot dashboard
with demo data**, then shows how to connect your own network, model, documents,
Telegram bot, and email.

You do **not** need to be a programmer. You need to copy a couple of files, type
a few commands, and wait for one big download the first time. Every command below
can be copied and pasted exactly as written.

> **The one thing NetCopilot needs: Docker.** Docker is a free tool that runs
> NetCopilot and everything it depends on (a database, the web dashboard, the AI
> connector) inside neat self-contained "containers", so you don't have to install
> Python, databases, or anything else by hand. Install Docker once and the rest is
> two files and one command.

---

## What you'll end up with

After this guide you'll have, all on your own machine:

- A **web dashboard** at `http://localhost:8080` showing a network map, findings, and an AI chat.
- A **graph database** (Neo4j) you can browse at `http://localhost:7474`.
- An **MCP server** at `http://localhost:3002/mcp` that other AI agents can connect to.
- An optional **Telegram bot** and **email reports**.

Nothing leaves your computer unless *you* configure a cloud AI model — and even
then, device names and addresses are automatically anonymized first.

---

## Step 1 — Install Docker

Pick your operating system.

### Windows 10/11

1. Download **Docker Desktop** from <https://www.docker.com/products/docker-desktop/> and run the installer.
2. When asked, keep the **"Use WSL 2"** option ticked (this is the modern, recommended engine — the installer sets it up for you).
3. Restart your computer if it asks.
4. Open **Docker Desktop** from the Start menu and wait until the whale icon in the taskbar stops animating — that means Docker is running.

> Windows users will type the commands below in **PowerShell** or **Windows
> Terminal** (search for "PowerShell" in the Start menu).

### macOS

1. Download **Docker Desktop** from <https://www.docker.com/products/docker-desktop/> (choose the Apple-Silicon or Intel build to match your Mac).
2. Open the downloaded `.dmg` and drag Docker to Applications.
3. Launch Docker from Applications and wait for the whale icon in the menu bar to settle.

> Mac users type commands in the **Terminal** app (Applications → Utilities → Terminal).

### Linux

Install Docker Engine + the Compose plugin using your distribution's instructions
at <https://docs.docker.com/engine/install/>. After installing, make sure your
user can run Docker without `sudo` (the "post-install" steps on that page), or
prefix the commands below with `sudo`.

### Check Docker works

Open your terminal (PowerShell / Terminal) and type:

```bash
docker --version
docker compose version
```

You should see version numbers for both. If you do, Docker is ready.

---

## Step 2 — Get NetCopilot onto your computer

If you have **git** installed:

```bash
git clone <repository-url>
cd netcopilot
```

(Replace `<repository-url>` with the address you were given.)

No git? Download the project as a **ZIP** from its web page, unzip it, then in
your terminal move into the unzipped folder. For example on Windows:

```powershell
cd Downloads\netcopilot
```

You're in the right folder if `ls` (macOS/Linux) or `dir` (Windows) shows files
like `docker-compose.yml` and `.env.example`.

---

## Step 3 — Create your two settings files

NetCopilot ships **example** settings files. You copy them once and edit the
copies. (The copies are private and never shared.)

```bash
cp .env.example .env
cp models.example.yaml models.yaml
```

> On Windows PowerShell, use `copy` instead of `cp`:
> ```powershell
> copy .env.example .env
> copy models.example.yaml models.yaml
> ```

Now open the new **`.env`** file in any text editor (Notepad on Windows, TextEdit
on Mac, or VS Code) and set a database password. Find this line:

```
NEO4J_PASSWORD=change-me-to-a-strong-password
```

Change it to a password of your choice, for example:

```
NEO4J_PASSWORD=MyNetwork2026!
```

Save the file. **That is the only required setting.** Everything else in `.env`
is optional and can be added later (see "Make it yours" below).

---

## Step 4 — Start NetCopilot

In the project folder, run:

```bash
docker compose up
```

**The first time, this downloads and builds a large image (roughly 3–4 GB) and
can take 10–15 minutes** depending on your internet speed. This only happens once
— later starts take seconds. You'll see a lot of text scroll by; that's normal.

You'll know it's ready when you see the dashboard start, for example:

```
netcopilot-dashboard  | Uvicorn running on http://0.0.0.0:8080
```

> **Tip:** To run it quietly in the background instead, press `Ctrl+C` to stop,
> then start it with `docker compose up -d` (the `-d` means "detached"). You can
> watch the logs any time with `docker compose logs -f`.

---

## Step 5 — Open the dashboard

In your web browser, go to:

**<http://localhost:8080>**

The dashboard opens **empty** — NetCopilot ships no network data of its own. To
see it in action with safe, made-up data:

1. In the **inventory dropdown** (top right, next to the green button), leave
   **`Demo — campus network`** selected.
2. Click **▶ Run Now**.

It replays a bundled **synthetic 8-device campus** (3 routers, a core switch,
3 access switches, a firewall) — no real devices needed — and in a few seconds
the topology map and findings fill in. Everything here is invented data, safe to
click around in. (This is exactly the flow shown in the installation video.)

Other things you can open:

- **Neo4j database browser:** <http://localhost:7474> (log in with username `neo4j` and the password you set in `.env`).
- **MCP server (for AI agents):** <http://localhost:3002/mcp>

If you can see the demo dashboard, **the installation worked.** 🎉

---

## Everyday use

Run these from inside the project folder:

| What you want | Command |
|---|---|
| Start (in background) | `docker compose up -d` |
| See the live logs | `docker compose logs -f` |
| Stop (keeps your data) | `docker compose down` |
| Stop **and erase all data** | `docker compose down -v` |
| Update after getting new code | `git pull` then `docker compose up -d --build` |
| Restart just one part | `docker compose restart dashboard` |

Your data (the loaded network, ingested documents) lives in Docker "volumes" and
survives a normal `docker compose down`. Only `down -v` wipes it.

---

## Make it yours (all optional)

Each of these is added by editing `.env` (or `models.yaml`) and restarting with
`docker compose up -d`. Do them in any order, whenever you're ready.

### A. Use your own AI model (for the chat)

The dashboard, map, and findings work **without any AI** — only the **chat**
needs a model. Models are defined in `models.yaml` (copy `models.example.yaml`);
every entry appears in the chat's model dropdown.

**The golden rule: keys go in `.env`, never in `models.yaml`.** Each entry names
the *environment variable* that holds its key via `api_key_env` — the **name**
(e.g. `ANTHROPIC_API_KEY`), **not** the key itself. The key value lives only in
`.env` (gitignored). Putting the key in `api_key_env` is the #1 mistake — the
model then silently fails to authenticate and won't appear in the dropdown.

Three kinds of model:

- **Self-hosted (local / on-prem)** — Ollama, vLLM, etc. Data never leaves your
  network, so `anonymize: false`. Use `host.docker.internal` for a model on the
  *same* machine as Docker, or the server's IP for a remote box:
  ```yaml
  - id: gemma-local
    label: "Gemma 4 (local)"
    type: openai
    base_url: ${VLLM_BASE_URL}        # e.g. http://10.0.0.5:8000/v1 (set in .env)
    model: gemma-4-31b-it
    anonymize: false
  ```
- **Claude** (native API):
  ```yaml
  - id: claude
    label: "Claude (anonymized)"
    type: anthropic
    model: claude-sonnet-4-6
    api_key_env: ANTHROPIC_API_KEY    # the NAME, not the key
    anonymize: true
  ```
- **Gemini / GPT / any OpenAI-compatible** — `type: openai` with the provider's
  `base_url`:
  ```yaml
  - id: gemini
    label: "Gemini (anonymized)"
    type: openai
    base_url: https://generativelanguage.googleapis.com/v1beta/openai
    model: gemini-2.5-flash
    api_key_env: GEMINI_API_KEY       # the NAME, not the key
    anonymize: true
  ```

Put the actual keys in `.env`, then recreate so both files reload:
```
ANTHROPIC_API_KEY=...
GEMINI_API_KEY=...
VLLM_BASE_URL=http://your-llm-host:8000/v1
```
```bash
docker compose up -d --force-recreate dashboard
```

**Commercial models anonymize** device names/addresses before anything is sent;
**self-hosted models keep everything on-prem**. The dropdown only lists models
that are actually usable (key present, or `base_url` set) — so if one is missing,
its key isn't loaded yet (see Troubleshooting).

### B. Connect your network(s)

NetCopilot ships **no real network data** — you point it at yours. Every network
you add is its own **site**, isolated in the graph; add as many as you like. The
whole `inventory/` directory is gitignored, so your inventories and their
credentials never leave your machine.

**One network** — drop a single inventory file in `inventory/`:

```bash
cp examples/inventory.yaml inventory/my-network.yaml
```

Edit it — each device needs a `name`, a `mgmt_ip` (management address), and an
`os` (`ios-xe`, `ios-xr`, or `fortios`; the joined spellings `iosxe`/`iosxr` work
too). Put the device login in `.env`:

```
NETCOPILOT_SSH_USERNAME=your-username
NETCOPILOT_SSH_PASSWORD=your-password
NETCOPILOT_ENABLE_PASSWORD=your-enable-secret      # only if your devices use one
NETCOPILOT_FORTIGATE_API_TOKEN=your-fortigate-token # only if you have a FortiGate
```

**Multiple networks / tenants** — give each one a **self-contained folder** with
its own credentials, so nothing is shared and adding a tenant is just dropping a
folder:

```
inventory/
  customer-a/
    lab.yaml          # that tenant's devices (same shape as the file above)
    credentials.env   # that tenant's secrets (below)
  customer-b/
    lab.yaml
    credentials.env
```

Each `credentials.env` holds only that tenant's secrets:

```
NETCOPILOT_SSH_USERNAME=...
NETCOPILOT_SSH_PASSWORD=...
NETCOPILOT_ENABLE_PASSWORD=...
NETCOPILOT_FORTIGATE_API_TOKEN=...    # only if that tenant has a FortiGate
```

When you collect a folder tenant, NetCopilot loads **that folder's**
`credentials.env` for that run only — two tenants never share credentials.

**Either way:** restart (`docker compose up -d`), pick the network in the
**inventory dropdown**, and click **▶ Run Now**. NetCopilot connects from inside
the container (pyATS → NETCONF → RESTCONF → SSH), collects the live
configuration, and builds the map + findings under that site.

**Managing sites** — list or delete loaded runs (or use the 🗑 on a run /
inventory in the dashboard, which also removes its files):

```bash
docker compose exec dashboard python -m netcopilot.cli neo4j runs
docker compose exec dashboard python -m netcopilot.cli neo4j delete <run_id> --site <site>
```

### C. Add your own documents (RAG)

NetCopilot can answer questions grounded in your vendor PDFs (configuration
guides, hardening docs). The document store starts empty.

1. Put your PDF files in a folder named `knowledge_base` inside the project.
2. Load them into NetCopilot:
   ```bash
   docker compose exec dashboard python -m netcopilot.rag.ingest --docs-dir /app/knowledge_base
   ```
3. Ask document questions in the chat. You can add more PDFs and re-run the
   command any time.

### D. Use your own Telegram bot

The bot answers the same questions as the dashboard chat, from your phone, using
your default model.

1. **Create a bot** — in Telegram message **@BotFather**, send `/newbot`, and copy
   the token. Use a **dedicated** bot for this instance: a token allows only one
   active poller, so don't reuse a bot already running elsewhere (you'll get
   `409 Conflict`).
2. **Find your user ID** — message **@userinfobot**; it replies with your numeric
   ID (used to lock the bot to you).
3. **In `.env`:**
   ```
   TELEGRAM_BOT_TOKEN=the-token-from-botfather
   TELEGRAM_ALLOWED_USERS=your-numeric-id      # comma-separated; empty = anyone (not recommended)
   ```
4. **Start it** (recreate so the new env loads), then message your bot `/start`:
   ```bash
   docker compose up -d --force-recreate telegram
   ```

Like the chat, the bot uses your **default model** — keep that on a local model
for production questions so nothing leaves your network. If `/start` gets no
reply, see Troubleshooting.

### E. Send reports by email (your SMTP)

Reports always download as PDF. To **email** them, set your mail server in `.env`
(any RFC-5321 provider — this example uses Gmail):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=you@example.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_ADDRESS=you@example.com
SMTP_FROM_NAME=NetCopilot
```

Recreate to load it, then test from the **Report** tab — generate a report for a
site and email it to yourself:
```bash
docker compose up -d --force-recreate dashboard
```

> For Gmail and many providers you need an **app password** (enable 2-step
> verification, then create one) — your normal login password will fail auth.

A report contains real device names and findings, so for a **production** site
only email it to trusted recipients.

### F. Remove the bundled demo labs (production)

NetCopilot ships synthetic demo labs so you can see it working immediately. On a
production install you'll want them gone from the inventory dropdown — set one
variable in `.env` (no rebuild, no file edits):

```
NETCOPILOT_HIDE_DEMOS=1
```

Restart (`docker compose up -d dashboard`); the dropdown then shows only your own
inventories. Any demo run you already loaded can be removed with the 🗑 next to it.

---

## Troubleshooting

**The first build is taking forever.**
That's expected the first time (3–4 GB download + build, 10–15 minutes). Later
starts are fast. Make sure Docker Desktop is running and you have a stable
connection.

**"Port is already allocated" / "address already in use".**
Something else on your computer is using port 8080, 7474, 7687, or 3002. Either
close that program, or change the port in `.env` — for example add
`DASHBOARD_PORT=8090` and then open `http://localhost:8090` instead.

**The chat says no model is configured.**
That's normal until you do step **A** above. The rest of the dashboard still works.

**The chat can't reach my local LLM.**
From inside a container, your own machine is `host.docker.internal`, not
`localhost`. Use `http://host.docker.internal:<port>/v1` in `models.yaml`.

**A commercial model (Claude/Gemini/GPT) isn't in the dropdown.**
Its key isn't reaching the app. Check three things: the key is set in `.env` (not
commented out, and the file is named exactly `.env`, not `.env.txt`);
`models.yaml` uses `api_key_env: THE_VAR_NAME` (the **name**, never the key
itself); and you recreated the dashboard after editing
(`docker compose up -d --force-recreate dashboard`).

**A cloud model returns "429 Too Many Requests".**
That's the provider rate-limiting your key, not NetCopilot — usually a free-tier
quota (e.g. Gemini's `*-pro` models are tightly limited). Switch to a
higher-limit model (e.g. a `*-flash` variant), wait a minute, or enable billing
on the provider account.

**The Telegram bot doesn't respond.**
Check `docker compose logs telegram`. If the container **exited**, the token
isn't loaded (line commented, `.env.txt`, or you didn't `--force-recreate`). If
it's **running but silent**, `TELEGRAM_ALLOWED_USERS` likely has the wrong ID —
empty it to test, then set the right one (from @userinfobot). `409 Conflict`
means two pollers share one token (don't reuse a bot already running elsewhere).

**Reports download as PDF but the email never arrives.**
SMTP isn't authenticating. Check `SMTP_PASSWORD` is an **app password** (not your
login), `SMTP_HOST`/`SMTP_PORT` match your provider, and you recreated the
dashboard after editing `.env`. The PDF always generates; only emailing needs SMTP.

**Neo4j won't start / "set NEO4J_PASSWORD".**
You must set `NEO4J_PASSWORD` in `.env` (step 3). If you changed it after the
first run, the old password is still stored — run `docker compose down -v` to
reset (this erases data) and start again.

**It's slow or runs out of memory.**
NetCopilot is tuned for laptops, but the database needs some RAM. In Docker
Desktop → Settings → Resources, give Docker at least 4 GB of memory.

**Windows: "docker: command not found".**
Open Docker Desktop and wait for it to finish starting, then use PowerShell (not
the old Command Prompt). Make sure WSL 2 is enabled (the Docker installer offers
this).

**I changed `.env` but nothing happened.**
`.env` is read when a service *starts*. After editing it, recreate the affected
services so they pick up the new values:
`docker compose up -d --force-recreate dashboard watcher`.

**A value I set in `.env` isn't taking effect.**
Two common causes: the line is still **commented** (starts with `#` — remove it),
or your editor saved the file as **`.env.txt`** (Windows Notepad does this
silently). The file must be named exactly `.env`.

**My FortiGate (firewall) isn't collected.**
A FortiGate needs its **REST API token** — `NETCOPILOT_FORTIGATE_API_TOKEN` in
`.env`, or in that tenant's `credentials.env`. Without it the firewall is skipped
and the rest of the run still completes.

**I need to start completely fresh.**
```bash
docker compose down -v
docker compose up --build
```

---

## A note on security and privacy

- Your **`.env`** file holds passwords and keys. It is already excluded from
  version control — never share it or commit it.
- NetCopilot is **read-only on your network**: it collects and reports, it never
  changes device configuration.
- When you use a **commercial** AI model, device names, IP addresses, and other
  identifiers are **anonymized** before anything leaves your machine. **Local**
  models keep everything on-premises.

---

## Getting help

- The shorter overview lives in [README.md](README.md).
- Want to add support for a new device vendor? See [CONTRIBUTING.md](CONTRIBUTING.md).
- Licensed under Apache 2.0 — see [LICENSE](LICENSE).
