#!/usr/bin/env bash
# Configure an OMP profile to route supported providers through an OMP auth
# gateway. The gateway URL is always supplied by the caller.
#
#   AGENT_AUTH_URL=https://gateway.example.com ./agent-auth-setup.sh
#   ./agent-auth-setup.sh --url https://gateway.example.com [--profile work]
#
# When streamed into bash, put AGENT_AUTH_URL on bash (the right side of the
# pipe) so the installer receives it:
#
#   curl -fsSL https://example.com/agent-auth-setup.sh | \
#     AGENT_AUTH_URL=https://gateway.example.com bash
set -euo pipefail

readonly YQ_VERSION='v4.53.6'

fail() {
  printf 'setup failed: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: agent-auth-setup.sh [--url URL] [--profile NAME] [--reuse-key|--new-key]

  --url URL       OMP auth gateway base URL (or set AGENT_AUTH_URL)
  --profile NAME  Configure that OMP profile instead of the active/default one
  --reuse-key     Non-interactively choose the key already on this machine
  --new-key       Use AGENT_AUTH_TOKEN, or securely prompt for a new key
EOF
}

gateway_url="${AGENT_AUTH_URL:-}"
profile=''
key_choice="${AGENT_AUTH_KEY_CHOICE:-}"
while (( $# > 0 )); do
  case "$1" in
    --url)
      (( $# >= 2 )) || fail '--url needs a value'
      gateway_url="$2"
      shift 2
      ;;
    --url=*)
      gateway_url="${1#--url=}"
      shift
      ;;
    --profile)
      (( $# >= 2 )) || fail '--profile needs a value'
      profile="$2"
      shift 2
      ;;
    --profile=*)
      profile="${1#--profile=}"
      shift
      ;;
    --reuse-key)
      [[ -z "${key_choice}" || "${key_choice}" == same ]] || fail '--reuse-key conflicts with --new-key'
      key_choice='same'
      shift
      ;;
    --new-key)
      [[ -z "${key_choice}" || "${key_choice}" == new ]] || fail '--new-key conflicts with --reuse-key'
      key_choice='new'
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "${key_choice}" in
  ''|same|new) ;;
  *) fail 'AGENT_AUTH_KEY_CHOICE must be same or new' ;;
esac

command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v omp >/dev/null 2>&1 || fail 'omp is required; install OMP first'
[[ -n "${gateway_url}" ]] || fail 'set AGENT_AUTH_URL or pass --url'
[[ "${gateway_url}" != *[$' \t\r\n']* ]] || fail 'gateway URL must not contain whitespace'
[[ "${gateway_url}" != *'?'* && "${gateway_url}" != *'#'* ]] || fail 'gateway URL must not contain a query or fragment'
while [[ "${gateway_url}" == */ ]]; do gateway_url="${gateway_url%/}"; done

if [[ "${gateway_url}" =~ ^https://([^/]+)(/.*)?$ ]]; then
  authority="${BASH_REMATCH[1]}"
  [[ "${authority}" != *'@'* ]] || fail 'gateway URL must not contain credentials'
elif [[ "${gateway_url}" =~ ^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(/.*)?$ ]]; then
  :
else
  fail 'gateway URL must use HTTPS (HTTP is allowed only for loopback)'
fi

if [[ -n "${profile}" && ! "${profile}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
  fail 'profile names are [a-z0-9][a-z0-9._-]{0,63}'
fi

omp_args=()
if [[ -n "${profile}" ]]; then omp_args=(--profile "${profile}"); fi
agent_dir="$(omp "${omp_args[@]}" config path)" || fail 'could not resolve the OMP config path'
[[ "${agent_dir}" == /* && "${agent_dir}" != *$'\n'* ]] || fail 'omp config path did not return one absolute path'

umask 077
mkdir -p "${agent_dir}"

models="${agent_dir}/models.yml"
if [[ ! -e "${models}" && ! -L "${models}" && -e "${agent_dir}/models.yaml" ]]; then
  models="${agent_dir}/models.yaml"
fi
legacy_models=''
if [[ ! -e "${models}" && ! -L "${models}" \
  && ( -e "${agent_dir}/models.json" || -L "${agent_dir}/models.json" ) ]]; then
  [[ -f "${agent_dir}/models.json" ]] || fail "legacy models config is not a regular file: ${agent_dir}/models.json"
  legacy_models="${agent_dir}/models.json"
fi

# Preserve a caller's final symlink rather than replacing it with a regular file.
symlink_hops=0
while [[ -L "${models}" ]]; do
  ((symlink_hops += 1))
  (( symlink_hops <= 16 )) || fail 'models config has a symlink loop'
  link_target="$(readlink "${models}")" || fail "could not read symlink ${models}"
  if [[ "${link_target}" == /* ]]; then
    models="${link_target}"
  else
    models="$(cd -P "$(dirname "${models}")" && pwd)/${link_target}"
  fi
done
[[ ! -e "${models}" || -f "${models}" ]] || fail "models config is not a regular file: ${models}"

cache_home="${XDG_CACHE_HOME:-${HOME}/.cache}"
if [[ "${cache_home}" != /* ]]; then cache_home="${HOME}/.cache"; fi
cache_dir="${cache_home}/omp-agent-auth"
mkdir -p "${cache_dir}"
chmod 0700 "${cache_dir}"
scratch_dir="${cache_dir}/run-$$-${RANDOM}"
mkdir "${scratch_dir}"

candidate=''
token_tmp=''
backup_path=''
models_existed=0
config_applied=0
setup_committed=0
if [[ -f "${models}" ]]; then models_existed=1; fi

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if (( config_applied == 1 && setup_committed == 0 )); then
    if (( models_existed == 1 )); then
      if ! mv -f "${backup_path}" "${models}"; then
        printf 'setup rollback failed; original config remains at %s\n' "${backup_path}" >&2
      fi
    else
      rm -f "${models}"
    fi
  fi
  [[ -z "${token_tmp}" ]] || rm -f "${token_tmp}"
  [[ -z "${candidate}" ]] || rm -f "${candidate}"
  rm -rf "${scratch_dir}"
  exit "${status}"
}
trap cleanup EXIT

sha256_file() {
  local file="$1" output
  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "${file}")"
    printf '%s\n' "${output%% *}"
  elif command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 "${file}")"
    printf '%s\n' "${output%% *}"
  elif command -v openssl >/dev/null 2>&1; then
    output="$(openssl dgst -sha256 "${file}")"
    printf '%s\n' "${output##* }"
  else
    fail 'sha256sum, shasum, or openssl is required to verify the YAML helper'
  fi
}

resolve_yq() {
  if [[ -n "${AGENT_AUTH_YQ_BIN:-}" ]]; then
    [[ -x "${AGENT_AUTH_YQ_BIN}" ]] || fail "AGENT_AUTH_YQ_BIN is not executable: ${AGENT_AUTH_YQ_BIN}"
    printf '%s\n' "${AGENT_AUTH_YQ_BIN}"
    return
  fi

  local os arch asset expected target download actual
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}/${arch}" in
    Linux/x86_64|Linux/amd64)
      asset='yq_linux_amd64'
      expected='c5f056448f973ae7d39b5401949648a78f2dc1947d6a8eb65be60d5c504b9385'
      ;;
    Linux/aarch64|Linux/arm64)
      asset='yq_linux_arm64'
      expected='88a1016bc1d657375a35864e4f44b6f333df8ff97b559f51bba0adcb2169df09'
      ;;
    Darwin/x86_64|Darwin/amd64)
      asset='yq_darwin_amd64'
      expected='caa513cb04f3804b34d4752f0e0d7904fecb9e7cf1d34081289f83259319a7f6'
      ;;
    Darwin/arm64|Darwin/aarch64)
      asset='yq_darwin_arm64'
      expected='cceb0b8d71ea5294334121f8429f33f92b920e7217d904a2f9f35443968ac424'
      ;;
    *) fail "unsupported platform for the YAML helper: ${os}/${arch}" ;;
  esac

  target="${cache_dir}/${asset}-${YQ_VERSION}"
  if [[ -x "${target}" ]]; then
    actual="$(sha256_file "${target}")"
    if [[ "${actual}" == "${expected}" ]]; then
      printf '%s\n' "${target}"
      return
    fi
  fi

  download="${scratch_dir}/${asset}"
  curl --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
    --output "${download}" \
    "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${asset}"
  actual="$(sha256_file "${download}")"
  [[ "${actual}" == "${expected}" ]] || fail "checksum mismatch for ${asset} ${YQ_VERSION}"
  chmod 0700 "${download}"
  mv -f "${download}" "${target}"
  printf '%s\n' "${target}"
}

yq_bin="$(resolve_yq)"

token_dir="${agent_dir}/agent-auth"
token_file="${token_dir}/token"
[[ ! -e "${token_file}" || -f "${token_file}" ]] || fail "stored gateway key is not a regular file: ${token_file}"
[[ ! -L "${token_file}" ]] || fail "stored gateway key must not be a symlink: ${token_file}"

stored_token=''
stored_source=''
if [[ -f "${token_file}" ]]; then
  stored_token="$(<"${token_file}")"
  if [[ -n "${stored_token}" ]]; then stored_source="${token_file/#${HOME}/\~}"; fi
fi

# Recover a key embedded by an earlier setup only when its route already points
# at this exact gateway. A personal provider key is never treated as reusable.
config_token=''
if [[ -z "${stored_token}" && -f "${models}" ]]; then
  config_token="$(
    GATEWAY_URL="${gateway_url}" AGENT_AUTH_YQ_ACTION='existing-key' \
      "${yq_bin}" eval -r '
        [ .providers."openai-codex", .providers.anthropic ] |
        map(select(
          (type == "!!map") and
          (.baseUrl == strenv(GATEWAY_URL)) and
          (.transport == "pi-native") and
          ((.apiKey // "") | type == "!!str") and
          ((.apiKey // "") | test("^!") | not)
        )) |
        map(.apiKey) | unique |
        select(length == 1) | .[0]
      ' "${models}" 2>/dev/null || true
  )"
  if [[ -n "${config_token}" ]]; then
    stored_token="${config_token}"
    stored_source="${models/#${HOME}/\~}"
  fi
fi

explicit_token="${AGENT_AUTH_TOKEN:-}"
legacy_env_token="${AUTH_GATEWAY_TOKEN:-}"
existing_token="${stored_token}"
existing_source="${stored_source}"
if [[ -z "${existing_token}" && -n "${explicit_token}" ]]; then
  existing_token="${explicit_token}"
  existing_source='AGENT_AUTH_TOKEN'
elif [[ -z "${existing_token}" && -n "${legacy_env_token}" ]]; then
  existing_token="${legacy_env_token}"
  existing_source='AUTH_GATEWAY_TOKEN'
fi

has_tty=0
if { exec 9<>/dev/tty; } 2>/dev/null; then
  has_tty=1
  exec 9>&-
fi

prompt_choice() {
  local answer
  printf 'A gateway key already exists (%s).\n' "${existing_source}" >/dev/tty
  if [[ -n "${explicit_token}" && "${explicit_token}" != "${existing_token}" ]]; then
    printf 'AGENT_AUTH_TOKEN contains a different key; choose new to use it.\n' >/dev/tty
  fi
  while true; do
    printf '  1) Set up using the same key\n  2) Set up using a new key\nChoice [1-2]: ' >/dev/tty
    IFS= read -r answer </dev/tty || fail 'could not read key choice'
    case "${answer}" in
      1|same|'') key_choice='same'; return ;;
      2|new) key_choice='new'; return ;;
      *) printf 'Enter 1 or 2.\n' >/dev/tty ;;
    esac
  done
}

prompt_new_token() {
  local entered
  (( has_tty == 1 )) || fail 'set AGENT_AUTH_TOKEN or run from an interactive terminal to enter a new key'
  printf 'Paste the minted gateway key (input is hidden): ' >/dev/tty
  IFS= read -r -s entered </dev/tty || fail 'could not read gateway key'
  printf '\n' >/dev/tty
  [[ -n "${entered}" ]] || fail 'gateway key cannot be empty'
  printf '%s' "${entered}"
}

if [[ -n "${existing_token}" ]]; then
  if [[ -z "${key_choice}" ]]; then
    if (( has_tty == 1 )); then
      prompt_choice
    elif [[ "${existing_source}" == 'AGENT_AUTH_TOKEN' ]]; then
      key_choice='same'
    else
      fail 'a gateway key already exists; rerun with --reuse-key or --new-key'
    fi
  fi
else
  [[ "${key_choice}" != same ]] || fail '--reuse-key was requested, but no existing gateway key was found'
  key_choice='new'
fi

token=''
if [[ "${key_choice}" == same ]]; then
  token="${existing_token}"
elif [[ -n "${explicit_token}"   && ( -z "${stored_token}" || "${explicit_token}" != "${existing_token}" ) ]]; then
  token="${explicit_token}"
else
  token="$(prompt_new_token)"
fi
[[ -n "${token}" ]] || fail 'gateway key cannot be empty'
[[ "${token}" != *$'\n'* && "${token}" != *$'\r'* ]] || fail 'gateway key must be one line'

header_file="${scratch_dir}/authorization-header"
printf 'Authorization: Bearer %s\n' "${token}" > "${header_file}"
chmod 0600 "${header_file}"
catalog_file="${scratch_dir}/catalog.json"
if ! catalog_status="$(curl --silent --show-error --output "${catalog_file}" --write-out '%{http_code}' \
  --header "@${header_file}" --connect-timeout 10 --max-time 30 \
  "${gateway_url}/v1/models")"; then
  fail 'could not reach the gateway model catalog'
fi
case "${catalog_status}" in
  200) ;;
  401|403) fail "the gateway refused this key (${catalog_status})" ;;
  *) fail "gateway model catalog returned HTTP ${catalog_status}" ;;
esac

model_ids_file="${scratch_dir}/model-ids"
if ! AGENT_AUTH_YQ_ACTION='catalog-model-ids' "${yq_bin}" eval -r \
  '.data[] | select((.id | type) == "!!str") | .id' "${catalog_file}" > "${model_ids_file}"; then
  fail 'gateway model catalog is not valid JSON'
fi
providers=()
has_openai=0
has_anthropic=0
while IFS= read -r model_id; do
  [[ -n "${model_id}" ]] || continue
  case "${model_id}" in
    openai-codex/*) has_openai=1 ;;
    anthropic/*) has_anthropic=1 ;;
  esac
done < "${model_ids_file}"
if (( has_openai == 1 )); then providers+=('openai-codex'); fi
if (( has_anthropic == 1 )); then providers+=('anthropic'); fi
(( ${#providers[@]} > 0 )) || fail 'gateway advertises no supported providers'

# An invalid body must get past bearer auth and reach the OMP gateway's body
# validator. This proves the key can use the model-call route before config moves.
probe_body="${scratch_dir}/probe.json"
printf '{}\n' > "${probe_body}"
if ! probe_status="$(curl --silent --show-error --output "${scratch_dir}/probe-response" --write-out '%{http_code}' \
  --request POST --header "@${header_file}" --header 'Content-Type: application/json' \
  --data-binary "@${probe_body}" --connect-timeout 10 --max-time 30 \
  "${gateway_url}/v1/pi/stream")"; then
  fail 'could not reach the gateway model-call route'
fi
[[ "${probe_status}" == 400 ]] || fail "gateway model-call route returned HTTP ${probe_status}; expected its 400 body validation"
rm -f "${header_file}"

route_expression='
  (.providers[strenv(PROVIDER)] | type) == "!!map" and
  .providers[strenv(PROVIDER)].baseUrl == strenv(GATEWAY_URL) and
  .providers[strenv(PROVIDER)].apiKey == strenv(GATEWAY_TOKEN) and
  .providers[strenv(PROVIDER)].transport == "pi-native"
'
config_needs_update=1
if (( models_existed == 1 )); then
  config_needs_update=0
  for provider in "${providers[@]}"; do
    if ! PROVIDER="${provider}" GATEWAY_URL="${gateway_url}" GATEWAY_TOKEN="${token}" \
      AGENT_AUTH_YQ_ACTION='route-matches' "${yq_bin}" eval -e \
      "${route_expression}" "${models}" >/dev/null 2>&1; then
      config_needs_update=1
      break
    fi
  done
fi

config_state='unchanged'
if (( config_needs_update == 1 )); then
  source_file="${models}"
  if (( models_existed == 0 )); then
    if [[ -n "${legacy_models}" ]]; then
      legacy_home="${scratch_dir}/legacy-home"
      legacy_agent_dir="${legacy_home}/.omp/agent"
      mkdir -p "${legacy_agent_dir}"
      cp -p "${legacy_models}" "${legacy_agent_dir}/models.json"
      if ! (
        cd "${legacy_home}"
        HOME="${legacy_home}" PI_CONFIG_DIR='.omp' PI_CODING_AGENT_DIR="${legacy_agent_dir}" \
          OMP_PROFILE='' PI_PROFILE='' \
          XDG_CONFIG_HOME="${legacy_home}/.config" XDG_DATA_HOME="${legacy_home}/.local/share" \
          XDG_STATE_HOME="${legacy_home}/.local/state" XDG_CACHE_HOME="${legacy_home}/.cache" \
          omp models --json > "${scratch_dir}/legacy-models.json"
      ); then
        fail "OMP could not migrate ${legacy_models/#${HOME}/\~}"
      fi
      source_file="${legacy_agent_dir}/models.yml"
      [[ -f "${source_file}" ]] || fail "OMP did not migrate ${legacy_models/#${HOME}/\~}"
    else
      source_file="${scratch_dir}/empty-models.yml"
      printf '{}\n' > "${source_file}"
    fi
  fi

  merge_expression='
    . = (. // {}) |
    select(type == "!!map") |
    .providers = (.providers // {}) |
    select((.providers | type) == "!!map")
  '
  if (( has_openai == 1 )); then
    merge_expression+=' |
      select(.providers."openai-codex" == null or (.providers."openai-codex" | type) == "!!map") |
      .providers."openai-codex" = ((.providers."openai-codex" // {}) * {
        "baseUrl": strenv(GATEWAY_URL),
        "apiKey": strenv(GATEWAY_TOKEN),
        "transport": "pi-native"
      })
    '
  fi
  if (( has_anthropic == 1 )); then
    merge_expression+=' |
      select(.providers.anthropic == null or (.providers.anthropic | type) == "!!map") |
      .providers.anthropic = ((.providers.anthropic // {}) * {
        "baseUrl": strenv(GATEWAY_URL),
        "apiKey": strenv(GATEWAY_TOKEN),
        "transport": "pi-native"
      })
    '
  fi
  candidate="${models}.agent-auth.$$-${RANDOM}.tmp"
  if ! HAS_OPENAI="${has_openai}" HAS_ANTHROPIC="${has_anthropic}" \
    GATEWAY_URL="${gateway_url}" GATEWAY_TOKEN="${token}" AGENT_AUTH_YQ_ACTION='merge-config' \
    "${yq_bin}" eval -e "${merge_expression}" "${source_file}" > "${candidate}"; then
    fail "could not merge gateway settings into ${models/#${HOME}/\~}"
  fi
  chmod 0600 "${candidate}"

  if (( models_existed == 1 )); then
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_path="${models}.pre-agent-auth.${stamp}.$$"
    cp -p "${models}" "${backup_path}"
    chmod 0600 "${backup_path}"
  fi
  mv -f "${candidate}" "${models}"
  candidate=''
  config_applied=1
  config_state='updated'
else
  chmod 0600 "${models}"
fi

for provider in "${providers[@]}"; do
  if ! PROVIDER="${provider}" GATEWAY_URL="${gateway_url}" GATEWAY_TOKEN="${token}" \
    AGENT_AUTH_YQ_ACTION='verify-config' "${yq_bin}" eval -e \
    "${route_expression}" "${models}" >/dev/null; then
    fail "gateway settings did not survive the write for ${provider}"
  fi
done

# Exercise OMP's real loader after the atomic write. This catches schema or
# version mismatches that a YAML parser alone cannot see.
omp_models_file="${scratch_dir}/omp-models.json"
if ! omp "${omp_args[@]}" models --json > "${omp_models_file}"; then
  fail 'OMP could not load the merged models config; update OMP and rerun'
fi
listed_providers_file="${scratch_dir}/omp-providers"
if ! AGENT_AUTH_YQ_ACTION='omp-providers' "${yq_bin}" eval -r \
  '.models[] | select((.provider | type) == "!!str") | .provider' \
  "${omp_models_file}" > "${listed_providers_file}"; then
  fail 'OMP returned an unreadable model list'
fi
for provider in "${providers[@]}"; do
  found=0
  while IFS= read -r listed; do
    if [[ "${listed}" == "${provider}" ]]; then found=1; break; fi
  done < "${listed_providers_file}"
  (( found == 1 )) || fail "OMP did not load any ${provider} models through the gateway config"
done

mkdir -p "${token_dir}"
chmod 0700 "${token_dir}"
if [[ ! -f "${token_file}" || "$(<"${token_file}")" != "${token}" ]]; then
  token_tmp="${token_file}.tmp.$$-${RANDOM}"
  printf '%s\n' "${token}" > "${token_tmp}"
  chmod 0600 "${token_tmp}"
  mv -f "${token_tmp}" "${token_file}"
else
  chmod 0600 "${token_file}"
fi

setup_committed=1
printf '\nOMP gateway ready\n'
printf '  gateway    %s\n' "${gateway_url}"
printf '  providers  %s\n' "$(IFS=', '; printf '%s' "${providers[*]}")"
printf '  models     %s (%s)\n' "${models/#${HOME}/\~}" "${config_state}"
printf '  key        %s (0600)\n' "${token_file/#${HOME}/\~}"
if [[ -n "${backup_path}" ]]; then
  printf '  backup     %s\n' "${backup_path/#${HOME}/\~}"
fi
if [[ -n "${profile}" ]]; then
  printf '\nRun: omp --profile %s\n' "${profile}"
else
  printf '\nRun: omp\n'
fi
