#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FLY_TOML="${FLY_TOML:-${REPO_ROOT}/fly.toml}"

log() {
  echo "[fly-mongo] $*"
}

fatal() {
  echo "[fly-mongo] ERROR: $*" >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fatal "Required command '$cmd' is not installed or not on PATH."
}

parse_fly_app() {
  local configured_app=""
  if [[ -f "$FLY_TOML" ]]; then
    configured_app="$(awk -F"'" '/^app =/ {print $2; exit}' "$FLY_TOML" || true)"
  fi
  [[ -n "${configured_app}" ]] || fatal "Unable to infer app name from ${FLY_TOML}. Set FLY_APP explicitly."
  echo "$configured_app"
}

require_cmd fly
require_cmd python3

parse_primary_region() {
  local configured_region=""
  if [[ -f "$FLY_TOML" ]]; then
    configured_region="$(awk -F"'" '/^primary_region =/ {print $2; exit}' "$FLY_TOML" || true)"
  fi
  echo "$configured_region"
}

API_APP="${FLY_API_APP:-${FLY_APP:-$(parse_fly_app)}}"
PRIMARY_REGION="${FLY_PRIMARY_REGION:-$(parse_primary_region)}"
MONGO_APP="${FLY_MONGO_APP:-${API_APP}-mongo}"
REGION="${FLY_MONGO_REGION:-${PRIMARY_REGION:-iad}}"
ORG_FLAG=()
if [[ -n "${FLY_ORG:-}" ]]; then
  ORG_FLAG=(--org "$FLY_ORG")
fi
VOLUME_NAME="${MONGO_VOLUME_NAME:-mongo_data}"
VOLUME_SIZE="${MONGO_VOLUME_SIZE:-5}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:7}"
MONGO_MACHINE_NAME="${MONGO_MACHINE_NAME:-mongo-primary}"
MONGO_VM_SIZE="${MONGO_VM_SIZE:-shared-cpu-1x}"
MONGO_DB_NAME="${MONGO_DB_NAME:-letsplay}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_SECRET_NAME="${MONGO_SECRET_NAME:-MONGODB_URI}"
MONGO_COMMAND="${MONGO_COMMAND:-mongod --bind_ip_all --ipv6 --port ${MONGO_PORT} --dbpath /data/db}"
MONGO_FORCE_RECREATE="${MONGO_FORCE_RECREATE:-false}"

log "API app=${API_APP}"
log "Mongo app=${MONGO_APP} (region=${REGION})"

app_exists() {
  if fly status --app "$1" >/dev/null 2>&1; then
    echo "yes"
  else
    echo "no"
  fi
}

ensure_app() {
  if [[ "$(app_exists "$MONGO_APP")" == "yes" ]]; then
    log "Mongo app '${MONGO_APP}' already exists; skipping creation."
    return
  fi

  log "Creating Fly app '${MONGO_APP}'..."
  if [[ ${#ORG_FLAG[@]} -gt 0 ]]; then
    fly apps create "$MONGO_APP" --machines "${ORG_FLAG[@]}"
  else
    fly apps create "$MONGO_APP" --machines
  fi
}

volume_exists() {
  local volumes_json
  volumes_json="$(fly volumes list --app "$MONGO_APP" --json 2>/dev/null || echo "[]")"
  python3 -c 'import json, sys
name = sys.argv[1]
raw = sys.stdin.read().strip()
data = json.loads(raw or "[]")
if isinstance(data, dict):
    data = data.get("Volumes") or data.get("data") or []
print("yes" if any((v.get("Name") or v.get("name")) == name for v in data) else "no")' \
    "$VOLUME_NAME" <<<"$volumes_json"
}

machine_exists() {
  local machines_json
  machines_json="$(fly machines list --app "$MONGO_APP" --json 2>/dev/null || echo "[]")"
  python3 -c 'import json, sys
name = sys.argv[1]
raw = sys.stdin.read().strip()
machines = json.loads(raw or "[]")
if isinstance(machines, dict):
    machines = machines.get("machines") or []
print("yes" if any(m.get("name") == name for m in machines) else "no")' \
    "$MONGO_MACHINE_NAME" <<<"$machines_json"
}

machine_id() {
  local machines_json
  machines_json="$(fly machines list --app "$MONGO_APP" --json 2>/dev/null || echo "[]")"
  python3 -c 'import json, sys
name = sys.argv[1]
raw = sys.stdin.read().strip()
machines = json.loads(raw or "[]")
if isinstance(machines, dict):
    machines = machines.get("machines") or []
for m in machines:
    if m.get("name") == name:
        print(m.get("id") or "")
        break' "$MONGO_MACHINE_NAME" <<<"$machines_json"
}

ensure_volume() {
  if [[ "$(volume_exists)" == "yes" ]]; then
    log "Volume '${VOLUME_NAME}' already exists; skipping creation."
    return
  fi

  log "Creating volume '${VOLUME_NAME}' (${VOLUME_SIZE} GB) in region ${REGION} (app=${MONGO_APP})..."
  fly volumes create "$VOLUME_NAME" \
    --app "$MONGO_APP" \
    --region "$REGION" \
    --size "$VOLUME_SIZE" \
    --yes
}

ensure_machine() {
  local existing_id=""
  existing_id="$(machine_id)"
  if [[ -n "$existing_id" ]]; then
    if [[ "$MONGO_FORCE_RECREATE" == "true" ]]; then
      log "Destroying existing Mongo machine '${MONGO_MACHINE_NAME}' (id=${existing_id}) for recreation..."
      fly machines destroy --app "$MONGO_APP" --force "$existing_id"
    else
      log "Mongo machine '${MONGO_MACHINE_NAME}' already exists; skipping creation."
      return
    fi
  fi

  log "Launching Mongo machine '${MONGO_MACHINE_NAME}' in app ${MONGO_APP} using ${MONGO_IMAGE}..."
  IFS=' ' read -r -a mongo_cmd <<<"$MONGO_COMMAND"
  fly machines run "$MONGO_IMAGE" \
    --app "$MONGO_APP" \
    --name "$MONGO_MACHINE_NAME" \
    --region "$REGION" \
    --volume "${VOLUME_NAME}:/data/db" \
    --vm-size "$MONGO_VM_SIZE" \
    --restart always \
    --env "MONGO_INITDB_DATABASE=${MONGO_DB_NAME}" \
    --detach \
    -- "${mongo_cmd[@]}"
  log "Mongo machine created."
}

resolve_private_ip() {
  local attempts=0
  local ip=""
  while [[ $attempts -lt 10 ]]; do
    ip="$(fly machines list --app "$MONGO_APP" --json 2>/dev/null | python3 -c 'import json, sys
name = sys.argv[1]
raw = sys.stdin.read().strip()
machines = json.loads(raw or "[]")
if isinstance(machines, dict):
    machines = machines.get("machines") or []
for machine in machines:
    if machine.get("name") == name:
        direct = machine.get("private_ip") or machine.get("privateIp")
        if direct:
            print(direct)
            sys.exit(0)
        for ip_obj in machine.get("ips", []):
            kind = ip_obj.get("type") or ip_obj.get("kind")
            if kind in ("private", "privatenet"):
                print(ip_obj.get("address") or ip_obj.get("ip") or "")
                sys.exit(0)
print("")' "$MONGO_MACHINE_NAME")"
    if [[ -n "$ip" ]]; then
      echo "$ip"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 3
  done
  return 1
}

set_secret() {
  local mongo_ip="$1"
  local host="$mongo_ip"
  if [[ "$host" == *:* && "$host" != \[* ]]; then
    host="[${host}]"
  fi
  local uri="mongodb://${host}:${MONGO_PORT}/${MONGO_DB_NAME}"

  log "Setting secret ${MONGO_SECRET_NAME} on API app '${API_APP}' to ${uri}"
  fly secrets set "${MONGO_SECRET_NAME}=${uri}" --app "$API_APP"
}

ensure_app
ensure_volume
ensure_machine

log "Resolving Mongo machine private IP..."
if ! PRIVATE_IP="$(resolve_private_ip)"; then
  fatal "Unable to resolve private IP for machine '${MONGO_MACHINE_NAME}'. Check 'fly machines list --app ${MONGO_APP}'."
fi
log "Mongo private IP: ${PRIVATE_IP}"

set_secret "$PRIVATE_IP"

log "All done! Deploy (or redeploy) the API app '${API_APP}' with 'fly deploy' so it picks up the new ${MONGO_SECRET_NAME} secret."
