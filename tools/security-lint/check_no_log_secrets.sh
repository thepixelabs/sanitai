#!/usr/bin/env bash
# Fails CI if any tracing macro references matched_raw.
# Run from workspace root: bash tools/security-lint/check_no_log_secrets.sh
set -euo pipefail

if git grep -n 'tracing::.*matched_raw' -- '*.rs'; then
    echo "SECURITY LINT FAIL: matched_raw passed to a tracing macro." >&2
    echo "matched_raw must never appear in logs. Use detector_id, byte lengths, counts only." >&2
    exit 1
fi
echo "Security lint passed: no tracing calls reference matched_raw."
