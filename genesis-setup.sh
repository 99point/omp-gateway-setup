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
  'https://raw.githubusercontent.com/99point/omp-gateway-setup/a1100cb12ad5cf9b3806cc65732088eea60d5040/agent-auth-setup.sh' \
  | bash -s -- "$@" --url 'https://genesis.99point.co'
