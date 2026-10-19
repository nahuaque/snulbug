# Always-on share runtime

Use the existing `snulbug mcp share run DIRECTORY` command for a long-lived
gateway. It runs in the foreground; systemd, launchd, or a container restart
policy owns whole-gateway restarts. There is no separate daemon or new CLI.
Create and review the share first using [MCP share sessions](mcp-share.md).

## Tunnel ownership

For ngrok and SSH shares, `share run` automatically starts and supervises the
managed tunnel independently of the web console. It uses the same generated
provider config and commands; existing shares need no new generated layout.
ngrok still uses `tunnel/ngrok-agent.yml` plus the separately attached Cloud
Endpoint Traffic Policy. SSH still uses the generated reverse-forward target.
See the [ngrok walkthrough](ngrok-end-to-end.md) for cloud setup.

```bash
/opt/snulbug/venv/bin/snulbug mcp share run /var/lib/snulbug/share --no-console
```

- `--no-console` disables only the UI, not tunnel startup or supervision.
- `--no-tunnel` disables automatic tunnel startup. The console can still
  explicitly start a managed tunnel; combine both flags for a headless gateway
  whose tunnel is externally managed.
- The existing console **Start tunnel** and **Stop tunnel** controls operate on
  the same managed process. An intentional stop cancels pending restarts and
  keeps the tunnel stopped until an explicit start.
- `generic`, `cloudflare`, `tailscale`, `pinggy`, `holepunch`, and other supported
  providers remain externally managed. Their generated setup commands still
  apply; snulbug does not start, restart, or stop those external processes.

Do not start a second provider process for an automatically managed endpoint.
The runtime supervises processes, not public reachability: a running ngrok or
SSH process does not prove that forwarding, DNS, TLS, authentication, or cloud
policy is correct. Use existing share doctor and health checks, including the
public URL checks, rather than treating a PID as readiness.
For ngrok, [doctor's policy drift inspection](ngrok-end-to-end.md#check-for-configuration-drift)
compares local configuration with the deployed Cloud Endpoint through optional,
read-only API access. Supply its API credential to the service account to enable
the same inspection from the console; it is separate from the agent authtoken.

## Runtime settings

The following optional table in the share's existing `snulbug.toml` shows all
defaults. Merge it into the file; do not replace the generated config or add a
second `[mcp.runtime]` table. Durations are in seconds.

```toml
[mcp.runtime]
tunnel_autostart = true
restart_initial_seconds = 1.0
restart_max_seconds = 30.0
restart_max_attempts = 5
restart_reset_seconds = 60.0
tunnel_shutdown_timeout = 5.0
graceful_shutdown_timeout = 30.0
```

`tunnel_autostart = false` disables automatic startup in the same way as
`--no-tunnel`; an explicit console start remains available. `--no-tunnel`
overrides `tunnel_autostart = true` for that invocation.

An unexpected managed tunnel exit triggers bounded exponential crash restart:
the delay begins at `restart_initial_seconds`, doubles on each retry, and is
capped at `restart_max_seconds`. `restart_max_attempts` limits restart attempts,
not the initial launch. With defaults, a repeatedly crashing process gets at
most five retries, after delays of 1, 2, 4, 8, and 16 seconds.

After exhaustion, automatic retries stop. Fix the cause, then explicitly start
the tunnel through the console or restart the whole service. A healthy process
running continuously for `restart_reset_seconds` resets the retry budget; this
is process stability, not a successful public endpoint probe. An intentional
console stop is not a crash and never consumes a retry or triggers a restart.

Only the managed tunnel process is restarted here. The OS supervisor handles a
gateway process failure; it is not a public health watchdog and should not be
used to bypass exhausted tunnel retries. No MCP tool calls are retried or
replayed by this runtime. A broken connection can leave a tool's outcome
unknown; reconnecting does not make a repeated side effect safe.
The existing decision feed and session reports include
[request failure explanations](mcp-evidence.md#request-failure-explanations),
separating admission, upstream credentials/transport, and response-policy failures
without performing retries or adding background probes.

## Shutdown

On SIGTERM or SIGINT, Uvicorn stops accepting new work and drains in-flight
requests and streams. `graceful_shutdown_timeout` bounds that drain; at the
deadline, remaining work is cancelled. Only after the gateway drain/cancellation
does the runtime stop its managed tunnel. `tunnel_shutdown_timeout` bounds the
tunnel's termination wait before forced cleanup. Tunnel restart is suppressed
during shutdown. Externally managed provider processes remain their owner's
responsibility.

Give the outer supervisor more than the sum of these two timeouts plus cleanup
headroom. The recipes below use 45 seconds for the default 30-second drain and
5-second tunnel wait. Increase the supervisor timeout if you increase either
runtime setting. SIGKILL, a host crash, or a shorter supervisor deadline cannot
provide graceful draining.

## Deployment prerequisites

- Install a build containing this runtime into a fixed virtual environment.
  Use an absolute `snulbug` executable path, not an interactive shell's alias,
  `uv run`, or a login-shell activation script. Keep the installation and
  launcher files administrator-owned and non-service-writable.
- Use a dedicated unprivileged account. Create the share once at its persistent
  absolute path under that account; do not run `share create --force` at boot.
  Keep the same path inside a container, or reconcile recorded paths before
  moving an existing share.
- Persist the whole share directory: config, policy, `leases.json`, invite
  secrets, canonical session state, tunnel config, and evidence. Give the service
  account write access, restrict the directory to mode `0700`, and protect
  secret-bearing files with mode `0600`. Backups are secret-bearing too.
- Install `ngrok` or `ssh` on the service's explicit `PATH`. Complete ngrok's
  generated authtoken setup; a placeholder config will not start. For SSH,
  provision non-interactive credentials and verified `known_hosts` for that
  account. Do not disable host-key verification or depend on a desktop agent.
- Arrange the upstream service separately. A tunnel restart does not restart
  the upstream, renew expired leases, extend invite authorization, or repair
  cloud policy. Use [renewable automation invites](mcp-share.md#renewable-automation-invites)
  where a bot needs approved renewal rather than an unbounded lease.
- Keep the share console on loopback or disable it with `--no-console`, as these
  recipes do. Never add a public tunnel or shared HTTP route to its admin port
  or ngrok's inspection port. For remote administration, deliberately enable
  the loopback console and use authenticated SSH local forwarding.

Do not put tokens in unit files, plists, command arguments, images, or source
control. Where the generated configuration uses environment references, load
them from a protected env file. For example, `share.env` can contain:

```dotenv
SNULBUG_SHARE_TOKEN=replace-with-the-existing-share-token
```

This is an existing credential, not a request to mint a different token. Keep
secrets already stored in generated policy/provider files protected as well;
setting an env variable does not replace a literal ngrok authtoken placeholder.
Environment variables are still visible to sufficiently privileged local
processes. Treat service logs and container inspection access as sensitive.

For upstream service tokens, prefer the existing
[credential broker references](credential-brokers.md#always-on-upstream-credentials).
File sources support atomic replacement without a restart; environment-backed
sources require a service restart to pick up supervisor environment changes.
Live share doctor checks availability and hygiene, and status/report plus the
console's Auth drawer reuse its secret-free diagnostics. Run checks in the
service environment: local availability is not proof of upstream acceptance.

If the same tunnel exposes a web app or API, declare its
[HTTP mount contract](mcp-proxy.md#mount-contracts-and-readiness): explicit
auth ownership, methods, credential-header forwarding, and an optional safe
backend health endpoint. MCP lease revocation does not stop application access.
Use the existing share doctor and provider drawer to review both kinds of
exposure; application OIDC/session auth remains the app's responsibility.

## Linux: systemd

This example assumes an existing `snulbug` user/group, an installation at
`/opt/snulbug/venv`, and a share created at `/var/lib/snulbug/share`.
Store the env file at `/etc/snulbug/share.env`, owned by root with mode `0600`;
systemd reads it before dropping privileges. Install ngrok at
`/usr/local/bin/ngrok` or SSH at `/usr/bin/ssh`.

Install `/etc/systemd/system/snulbug-share.service`:

```ini
[Unit]
Description=snulbug MCP share gateway
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=exec
User=snulbug
Group=snulbug
WorkingDirectory=/var/lib/snulbug/share
Environment=HOME=/var/lib/snulbug
Environment=PATH=/usr/local/bin:/usr/bin:/bin
EnvironmentFile=/etc/snulbug/share.env
ExecStart=/opt/snulbug/venv/bin/snulbug mcp share run /var/lib/snulbug/share --no-console
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
KillMode=mixed
TimeoutStopSec=45s
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`KillMode=mixed` sends the initial SIGTERM to the gateway, allowing it to drain
before stopping its tunnel; leftover processes are still forcibly cleaned up.
The default control-group termination would signal the tunnel at the same time
as the gateway. See [systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html).
`Restart=on-failure` covers gateway failure, not tunnel retry exhaustion or an
intentional service stop. See [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now snulbug-share.service
sudo journalctl -u snulbug-share.service -f
```

Stop with `sudo systemctl stop snulbug-share.service`. After repairing a gateway
start failure that hit systemd's start limit, use `sudo systemctl reset-failed
snulbug-share.service`, then `sudo systemctl start snulbug-share.service`.
Use `sudo systemctl restart snulbug-share.service` for an explicit whole-service
restart, including recovery after exhausted tunnel retries.

## macOS: launchd

For service operation before login, use a LaunchDaemon, not a per-login
LaunchAgent. This example assumes an existing dedicated `snulbug` account/group
with home `/Users/snulbug`, an installation at `/opt/snulbug/venv`, and a share
at `/Users/snulbug/share`. Create `/Users/snulbug/Library/Logs/snulbug` for its
logs, owned by that account with mode `0700`. The machine must remain awake and
its share volume must be available; launchd cannot provide uptime during sleep.
See Apple's [launchd job guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

launchd has no systemd-style `EnvironmentFile`. Store
`/Users/snulbug/.config/snulbug/share.env` as mode `0600`, owned by `snulbug`,
inside mode `0700` directories. Use simple shell-compatible `KEY=value` entries
with quoted values where needed. The following root-owned, non-service-writable
launcher at `/usr/local/libexec/snulbug-share-run` only loads that trusted file
and replaces itself with the existing command; it is not a new daemon:

```sh
#!/bin/sh
set -eu
umask 077
set -a
. /Users/snulbug/.config/snulbug/share.env
set +a
export HOME=/Users/snulbug
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
exec /opt/snulbug/venv/bin/snulbug mcp share run /Users/snulbug/share --no-console
```

Install `/Library/LaunchDaemons/com.snulbug.share.plist`, owned by `root:wheel`
with mode `0644`; keep secrets out of it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.snulbug.share</string>
  <key>UserName</key>
  <string>snulbug</string>
  <key>GroupName</key>
  <string>snulbug</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/libexec/snulbug-share-run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/snulbug/share</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>ExitTimeOut</key>
  <integer>45</integer>
  <key>StandardOutPath</key>
  <string>/Users/snulbug/Library/Logs/snulbug/share.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/snulbug/Library/Logs/snulbug/share.err.log</string>
</dict>
</plist>
```

`KeepAlive` restarts a gateway that exits; `ThrottleInterval` limits rapid
launches, and `ExitTimeOut` leaves time for graceful shutdown. These are outer
process controls, not public health checks or the managed tunnel retry budget.
See Apple's [launchd.plist reference](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5).

```bash
sudo chmod 0755 /usr/local/libexec/snulbug-share-run
plutil -lint /Library/LaunchDaemons/com.snulbug.share.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.snulbug.share.plist
sudo launchctl print system/com.snulbug.share
```

For an orderly stop, use `sudo launchctl bootout system/com.snulbug.share`.
For an explicit restart, boot out, then bootstrap the plist again. Avoid
`launchctl kickstart -k` for a draining restart: it kills the existing process.
A direct signal while `KeepAlive` is enabled may cause a new gateway launch;
boot out to keep the service stopped. Arrange rotation for the log files.

## Container

Use a locally built image containing this runtime and the chosen provider
binary; no new published image is required. The generated
`containers/Dockerfile.gateway` is a starting point and installs from its
`snulbug-src/` snapshot of the checkout or installed package, not a published
snulbug image. Ensure that snapshot
contains the runtime. It does not install ngrok or SSH: add a verified,
architecture-matched Linux ngrok binary or install `openssh-client` in your
local build before using managed startup. Never copy provider credentials into
the image. In this example the resulting local tag is
`snulbug-share-runtime:local`, and snulbug is installed at
`/usr/local/bin/snulbug` with provider binaries on its `PATH`.

The following command is for a Linux Docker host. Create the share at
`/srv/snulbug/share` and keep its generated gateway bound to `127.0.0.1`.
Host networking lets the gateway and its managed tunnel use the existing
loopback origin and reach an upstream on the host's loopback interface without
changing generated tunnel config. Do not use this unchanged for Docker Desktop
or bridge networking; those require deliberate upstream/network configuration.
The example assumes the host service account has UID/GID `10001:10001` and owns
the persistent share; substitute your account's numeric IDs.

Protect `/etc/snulbug/share.env` on the host as root-owned with mode `0600`.
Use Docker's `KEY=value` env-file syntax, not shell `export` or shell expansion.
The privileged Docker invocation below can read that file; the container itself
runs as the unprivileged UID. Use a persistent read-write bind volume at the
same absolute path:

```bash
sudo docker run --detach --name snulbug-share \
  --pull=never \
  --init \
  --restart=unless-stopped \
  --stop-signal=SIGTERM \
  --stop-timeout=45 \
  --network=host \
  --user=10001:10001 \
  --env-file=/etc/snulbug/share.env \
  --env HOME=/srv/snulbug \
  --env PATH=/usr/local/bin:/usr/bin:/bin \
  --mount type=bind,src=/srv/snulbug/share,dst=/srv/snulbug/share \
  --workdir=/srv/snulbug/share \
  --entrypoint=/usr/local/bin/snulbug \
  snulbug-share-runtime:local \
  mcp share run /srv/snulbug/share --no-console
```

For SSH, also mount the service account's SSH config, private key, and verified
`known_hosts` read-only at `/srv/snulbug/.ssh`, with permissions readable only by
that UID. Do not mount a general-purpose personal SSH directory. For ngrok,
complete the authtoken configuration in the protected share volume.

`--init` forwards signals and reaps children; `--stop-timeout` allows draining
before forced termination. No console or inspection port is published. With
host networking, loopback binds are essential: it does not isolate listening
ports from the host. See [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/).

Use `sudo docker logs -f snulbug-share` for gateway output and
`sudo docker stop snulbug-share` for an orderly stop. Use
`sudo docker restart --timeout 45 snulbug-share` for an explicit restart. The
restart policy handles container exit, not a live gateway with exhausted tunnel
retries or failing public checks.

## Verify and operate

After starting or restarting, use the existing checks from an account and
network that can reach the intended client URL:

```bash
/opt/snulbug/venv/bin/snulbug mcp share status /var/lib/snulbug/share
/opt/snulbug/venv/bin/snulbug mcp share doctor /var/lib/snulbug/share \
  --url https://YOUR-PUBLIC-HOST/mcp
```

Use the corresponding paths on macOS or inside the container. An SSH share's
default client URL is loopback on the remote SSH host, not the gateway host;
verify from that remote side as described in
[plain SSH reverse tunnels](mcp-share.md#plain-ssh-reverse-tunnel). For ngrok,
verify the generated Traffic Policy is attached to the public Cloud Endpoint,
not just that the private internal Agent Endpoint is running.

If a tunnel repeatedly exits, inspect its existing console diagnostics and
provider log, fix credentials/configuration or duplicate agents, and explicitly
start it again. With `--no-console`, restart the OS service instead. Do not
automatically replay failed MCP tool calls as a recovery mechanism. Finish a
bounded sharing task with the existing [closeout flow](mcp-share.md#close-out);
stopping a process alone is not lease or invite revocation.
