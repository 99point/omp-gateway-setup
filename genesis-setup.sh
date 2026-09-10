#!/usr/bin/env bash
# Convenience entrypoint: the same reviewed client installer with the endpoint
# fixed to Genesis. It accepts ONLY keys minted at https://genesis.99point.co/admin;
# a key from another gateway is refused there. The generic installer asks for
# any endpoint and key: bash agent-auth-setup.sh
set +x
set -euo pipefail
unset AUTH_GATEWAY_TOKEN AGENT_AUTH_KEY_CHOICE
for arg in "$@"; do
  case "${arg}" in
    --url|--url=*) echo 'Genesis fixes the endpoint; omit --url (use agent-auth-setup.sh for other gateways).' >&2; exit 2 ;;
  esac
done

curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 \
  'https://raw.githubusercontent.com/99point/omp-gateway-setup/eca68c2bc6e7ff4b4d89b41d18b681ca5f7075e5/agent-auth-setup.sh' \
  | bash -s -- "$@" --url 'https://genesis.99point.co'
