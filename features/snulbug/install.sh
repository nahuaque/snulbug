#!/usr/bin/env bash
set -euo pipefail

INSTALL_SOURCE="${INSTALL_SOURCE:-github}"
VERSION="${VERSION:-latest}"
GITHUB_REF="${GITHUB_REF:-main}"
PACKAGE_SPEC="${PACKAGE_SPEC:-}"
EXTRAS="${EXTRAS:-discovery}"
MODE="${MODE:-cli}"
POLICY_PROFILE="${POLICY_PROFILE:-tunnel-safe}"
UPSTREAM="${UPSTREAM:-http://127.0.0.1:9000/mcp}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
REGISTRY="${REGISTRY:-.snulbug/fabric-members.json}"
REGISTRY_KEY="${REGISTRY_KEY:-snulbug:fabric:members}"
MEMBER_ID="${MEMBER_ID:-devcontainer}"
MEMBER_UPSTREAM="${MEMBER_UPSTREAM:-workspace=http://127.0.0.1:9000/mcp}"
TTL_SECONDS="${TTL_SECONDS:-60}"
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-20}"
WRITE_CONFIG="${WRITE_CONFIG:-true}"

SNULBUG_HOME="/usr/local/share/snulbug/devcontainer"
SNULBUG_VENV="/usr/local/snulbug"

ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates git
    rm -rf /var/lib/apt/lists/*
    return
  fi
  echo "snulbug Feature requires python3 or an apt-based image where python3 can be installed." >&2
  exit 1
}

ensure_venv_support() {
  if python3 -m venv --help >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends python3-venv
    rm -rf /var/lib/apt/lists/*
    return
  fi
  echo "snulbug Feature requires python3 venv support." >&2
  exit 1
}

ensure_git_when_needed() {
  if [ "${INSTALL_SOURCE}" != "github" ] && [[ "${PACKAGE_SPEC}" != *git+* ]]; then
    return
  fi
  if command -v git >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends git ca-certificates
    rm -rf /var/lib/apt/lists/*
    return
  fi
  echo "snulbug Feature requires git for GitHub installs." >&2
  exit 1
}

python_package_spec() {
  if [ -n "${PACKAGE_SPEC}" ]; then
    printf '%s\n' "${PACKAGE_SPEC}"
    return
  fi

  local extras_suffix=""
  if [ -n "${EXTRAS}" ]; then
    extras_suffix="[${EXTRAS}]"
  fi

  if [ "${INSTALL_SOURCE}" = "github" ]; then
    printf 'snulbug%s @ git+https://github.com/lbruhacs/snulbug@%s\n' "${extras_suffix}" "${GITHUB_REF}"
    return
  fi

  if [ "${VERSION}" = "latest" ]; then
    printf 'snulbug%s\n' "${extras_suffix}"
  else
    printf 'snulbug%s==%s\n' "${extras_suffix}" "${VERSION}"
  fi
}

write_defaults() {
  install -d "${SNULBUG_HOME}"
  {
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_MODE+x}" ]; then SNULBUG_DEVCONTAINER_MODE=%q; fi\n' "${MODE}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_POLICY_PROFILE+x}" ]; then SNULBUG_DEVCONTAINER_POLICY_PROFILE=%q; fi\n' "${POLICY_PROFILE}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_UPSTREAM+x}" ]; then SNULBUG_DEVCONTAINER_UPSTREAM=%q; fi\n' "${UPSTREAM}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_GATEWAY_PORT+x}" ]; then SNULBUG_DEVCONTAINER_GATEWAY_PORT=%q; fi\n' "${GATEWAY_PORT}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_REGISTRY+x}" ]; then SNULBUG_DEVCONTAINER_REGISTRY=%q; fi\n' "${REGISTRY}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_REGISTRY_KEY+x}" ]; then SNULBUG_DEVCONTAINER_REGISTRY_KEY=%q; fi\n' "${REGISTRY_KEY}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_MEMBER_ID+x}" ]; then SNULBUG_DEVCONTAINER_MEMBER_ID=%q; fi\n' "${MEMBER_ID}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_MEMBER_UPSTREAM+x}" ]; then SNULBUG_DEVCONTAINER_MEMBER_UPSTREAM=%q; fi\n' "${MEMBER_UPSTREAM}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_TTL_SECONDS+x}" ]; then SNULBUG_DEVCONTAINER_TTL_SECONDS=%q; fi\n' "${TTL_SECONDS}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_HEARTBEAT_INTERVAL+x}" ]; then SNULBUG_DEVCONTAINER_HEARTBEAT_INTERVAL=%q; fi\n' "${HEARTBEAT_INTERVAL}"
    printf 'if [ -z "${SNULBUG_DEVCONTAINER_WRITE_CONFIG+x}" ]; then SNULBUG_DEVCONTAINER_WRITE_CONFIG=%q; fi\n' "${WRITE_CONFIG}"
  } > "${SNULBUG_HOME}/defaults.env"
}

write_init_helper() {
  cat > /usr/local/bin/snulbug-devcontainer-init <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEFAULTS="/usr/local/share/snulbug/devcontainer/defaults.env"
if [ -f "${DEFAULTS}" ]; then
  # shellcheck disable=SC1090
  source "${DEFAULTS}"
fi

WORKSPACE="${1:-${SNULBUG_WORKSPACE:-${GITHUB_WORKSPACE:-${PWD}}}}"
cd "${WORKSPACE}"

WRITE_CONFIG="${SNULBUG_DEVCONTAINER_WRITE_CONFIG:-true}"
POLICY_PROFILE="${SNULBUG_DEVCONTAINER_POLICY_PROFILE:-tunnel-safe}"
UPSTREAM="${SNULBUG_DEVCONTAINER_UPSTREAM:-http://127.0.0.1:9000/mcp}"
GATEWAY_PORT="${SNULBUG_DEVCONTAINER_GATEWAY_PORT:-8080}"

if [ "${WRITE_CONFIG}" != "true" ]; then
  exit 0
fi

if [ "${POLICY_PROFILE}" != "none" ] && [ ! -e "policy.snulbug" ]; then
  snulbug mcp init "${POLICY_PROFILE}" --output policy.snulbug
fi

if [ ! -f "snulbug.toml" ]; then
  snulbug mcp config init --output snulbug.toml
  python3 - "$UPSTREAM" "$GATEWAY_PORT" <<'PY'
from pathlib import Path
import sys

path = Path("snulbug.toml")
text = path.read_text(encoding="utf-8")
text = text.replace('upstream = "http://127.0.0.1:9000"', f'upstream = "{sys.argv[1]}"')
text = text.replace("port = 8080", f"port = {int(sys.argv[2])}", 1)
path.write_text(text, encoding="utf-8")
PY
fi
EOF
  chmod 0755 /usr/local/bin/snulbug-devcontainer-init
}

write_agent_helper() {
  cat > /usr/local/bin/snulbug-devcontainer-agent <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEFAULTS="/usr/local/share/snulbug/devcontainer/defaults.env"
if [ -f "${DEFAULTS}" ]; then
  # shellcheck disable=SC1090
  source "${DEFAULTS}"
fi

WORKSPACE="${SNULBUG_WORKSPACE:-${GITHUB_WORKSPACE:-${PWD}}}"
MODE="${SNULBUG_DEVCONTAINER_MODE:-cli}"
REGISTRY="${SNULBUG_DEVCONTAINER_REGISTRY:-.snulbug/fabric-members.json}"
REGISTRY_KEY="${SNULBUG_DEVCONTAINER_REGISTRY_KEY:-snulbug:fabric:members}"
MEMBER_ID="${SNULBUG_DEVCONTAINER_MEMBER_ID:-devcontainer}"
MEMBER_UPSTREAM="${SNULBUG_DEVCONTAINER_MEMBER_UPSTREAM:-workspace=http://127.0.0.1:9000/mcp}"
TTL_SECONDS="${SNULBUG_DEVCONTAINER_TTL_SECONDS:-60}"
HEARTBEAT_INTERVAL="${SNULBUG_DEVCONTAINER_HEARTBEAT_INTERVAL:-20}"
PIDFILE="${WORKSPACE}/.snulbug/devcontainer-agent.pid"
LOGFILE="${WORKSPACE}/.snulbug/devcontainer-agent.log"

resolve_member_upstream() {
  local spec="$1"
  if [[ "${spec}" != codespaces:* ]]; then
    printf '%s\n' "${spec}"
    return
  fi

  local remainder="${spec#codespaces:}"
  local part1=""
  local part2=""
  local part3=""
  local extra=""
  IFS=':' read -r part1 part2 part3 extra <<< "${remainder}"

  local name="workspace"
  local port=""
  local path="/mcp"
  if [ -z "${part2}" ]; then
    port="${part1}"
  else
    name="${part1}"
    port="${part2}"
    path="${part3:-/mcp}"
  fi

  if [ -n "${extra}" ]; then
    echo "invalid Codespaces member upstream '${spec}'; expected codespaces:NAME:PORT[:PATH]" >&2
    exit 2
  fi
  if [ -z "${name}" ] || [ -z "${port}" ]; then
    echo "invalid Codespaces member upstream '${spec}'; expected codespaces:NAME:PORT[:PATH]" >&2
    exit 2
  fi
  if ! [[ "${port}" =~ ^[0-9]+$ ]]; then
    echo "invalid Codespaces member upstream port '${port}'" >&2
    exit 2
  fi

  local codespace_name="${SNULBUG_CODESPACE_NAME:-${CODESPACE_NAME:-}}"
  local domain="${SNULBUG_CODESPACES_PORT_FORWARDING_DOMAIN:-${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}}"
  domain="${domain%.}"
  if [ -z "${codespace_name}" ] || [ -z "${domain}" ]; then
    echo "Codespaces upstream inference requires CODESPACE_NAME and GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN" >&2
    exit 2
  fi
  if [[ "${path}" != /* ]]; then
    path="/${path}"
  fi

  printf '%s=https://%s-%s.%s%s\n' "${name}" "${codespace_name}" "${port}" "${domain}" "${path}"
}

run_agent() {
  cd "${WORKSPACE}"
  if [ "${MODE}" = "member-agent" ]; then
    local resolved_upstream
    resolved_upstream="$(resolve_member_upstream "${MEMBER_UPSTREAM}")"
    exec snulbug mcp fabric member agent "${MEMBER_ID}" \
      --registry "${REGISTRY}" \
      --registry-key "${REGISTRY_KEY}" \
      --upstream "${resolved_upstream}" \
      --ttl-seconds "${TTL_SECONDS}" \
      --interval "${HEARTBEAT_INTERVAL}" \
      --unregister-on-exit
  fi
  if [ "${MODE}" = "gateway" ]; then
    exec snulbug mcp proxy --config snulbug.toml
  fi
  echo "snulbug devcontainer mode is '${MODE}'; no background agent started."
}

start_agent() {
  mkdir -p "${WORKSPACE}/.snulbug"
  if [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" >/dev/null 2>&1; then
    exit 0
  fi
  nohup "$0" run > "${LOGFILE}" 2>&1 &
  echo "$!" > "${PIDFILE}"
}

stop_agent() {
  if [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" >/dev/null 2>&1; then
    kill "$(cat "${PIDFILE}")"
  fi
  rm -f "${PIDFILE}"
  if [ "${MODE}" = "member-agent" ]; then
    snulbug mcp fabric member unregister "${MEMBER_ID}" \
      --registry "${REGISTRY}" \
      --registry-key "${REGISTRY_KEY}" \
      --compact >/dev/null || true
  fi
}

case "${1:-run}" in
  run)
    run_agent
    ;;
  start)
    start_agent
    ;;
  stop)
    stop_agent
    ;;
  status)
    if [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" >/dev/null 2>&1; then
      echo "running $(cat "${PIDFILE}")"
    else
      echo "stopped"
    fi
    ;;
  *)
    echo "usage: snulbug-devcontainer-agent [run|start|stop|status]" >&2
    exit 2
    ;;
esac
EOF
  chmod 0755 /usr/local/bin/snulbug-devcontainer-agent
}

ensure_python
ensure_venv_support
ensure_git_when_needed
python3 -m venv "${SNULBUG_VENV}"
"${SNULBUG_VENV}/bin/python" -m pip install --upgrade pip
"${SNULBUG_VENV}/bin/python" -m pip install --upgrade "$(python_package_spec)"
ln -sf "${SNULBUG_VENV}/bin/snulbug" /usr/local/bin/snulbug

write_defaults
write_init_helper
write_agent_helper

echo "snulbug Feature installed. Run 'snulbug-devcontainer-init' from postCreateCommand to initialize a workspace."
