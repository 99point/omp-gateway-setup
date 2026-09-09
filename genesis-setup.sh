#!/usr/bin/env bash
set +x
set -euo pipefail

# Same reviewed client installer; this entrypoint always selects the new service.
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 \
  'https://raw.githubusercontent.com/99point/omp-gateway-setup/3ff908105d770d2a74aefe6e671b4278face801e/agent-auth-setup.sh' \
  | bash -s -- "$@" --url 'https://genesis.99point.co'
