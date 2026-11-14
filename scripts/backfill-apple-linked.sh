#!/usr/bin/env bash
# Run once after upgrading to 0.42.0. Marks every live account that already
# has an Apple link (an `identity_links` row `apple#<sub>` written before
# 0.42.0) with `apple_linked_at`, so its passkey tokens carry
# `arkavo_apple_linked: true`. 0.42.0 marks new links itself.
#
# Idempotent: an account already marked, or deleted, is left alone. Reads only
# `user_id` from the link rows, never a sealed token. Prints counts, no ids.
#
# Tables: DYNAMODB_IDENTITY_LINKS_TABLE and DYNAMODB_CREDENTIALS_TABLE, as the
# server reads them (unprefixed defaults). AWS_ENDPOINT_URL_DYNAMODB points it
# at DynamoDB Local.
set -euo pipefail
LINKS=${DYNAMODB_IDENTITY_LINKS_TABLE:-identity_links}
CREDS=${DYNAMODB_CREDENTIALS_TABLE:-credentials}
export AWS_PAGER=

ids=$(aws dynamodb scan --table-name "$LINKS" --consistent-read \
  --filter-expression 'begins_with(link_pk, :p)' \
  --expression-attribute-values '{":p":{"S":"apple#"}}' \
  --projection-expression user_id \
  --query 'Items[].user_id.S' --output text | tr '\t' '\n' | grep -v '^None$' | sort -u || true)

now_ms=$(($(date +%s) * 1000))
err=$(mktemp)
trap 'rm -f "$err"' EXIT
marked=0
skipped=0
for id in $ids; do
  if aws dynamodb update-item --table-name "$CREDS" \
    --key "{\"user_id\":{\"S\":\"$id\"}}" \
    --update-expression 'SET apple_linked_at = :now' \
    --condition-expression 'attribute_exists(user_id) AND attribute_not_exists(deleted_at) AND attribute_not_exists(apple_linked_at)' \
    --expression-attribute-values "{\":now\":{\"N\":\"$now_ms\"}}" 2>"$err"; then
    marked=$((marked + 1))
  elif grep -q ConditionalCheckFailed "$err"; then
    skipped=$((skipped + 1))
  else
    cat "$err" >&2
    exit 1
  fi
done
echo "accounts with an Apple link: marked $marked, already marked or deleted $skipped"
