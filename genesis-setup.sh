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
  'https://raw.githubusercontent.com/99point/omp-gateway-setup/0ebd28b8cc820f8eeb2eb907d5d82976336963ad/agent-auth-setup.sh' \
  | bash -s -- "$@" --url 'https://genesis.99point.co'
