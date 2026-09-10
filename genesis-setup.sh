#!/usr/bin/env bash
set +x
set -euo pipefail
unset AUTH_GATEWAY_TOKEN AGENT_AUTH_KEY_CHOICE
for arg in "$@"; do
  case "${arg}" in
    --url|--url=*) echo 'Genesis fixes the endpoint; omit --url.' >&2; exit 2 ;;
  esac
done

# Same reviewed client installer; this entrypoint always selects the new service.
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 \
  'https://raw.githubusercontent.com/99point/omp-gateway-setup/99a8e43322bbccd116a2c1be09aeffa33d10c2db/agent-auth-setup.sh' \
  | bash -s -- "$@" --url 'https://genesis.99point.co'
