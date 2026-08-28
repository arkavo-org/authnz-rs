#!/usr/bin/env bash
# Create all authnz-rs tables against DynamoDB Local.
set -euo pipefail
EP=${AWS_ENDPOINT_URL_DYNAMODB:-http://localhost:8000}
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-local} AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-local} AWS_REGION=${AWS_REGION:-us-east-1}
# awscli/botocore only resolve the default region from AWS_DEFAULT_REGION, not
# AWS_REGION (AWS_REGION is honored by the AWS SDKs the app itself uses, e.g.
# aws-sdk-dynamodb via aws_config::load_defaults, but not by this CLI) —
# export both so `aws dynamodb create-table` below doesn't fail with
# "You must specify a region".
export AWS_DEFAULT_REGION="$AWS_REGION"

# Wait for DynamoDB Local to accept connections before creating tables —
# otherwise a slow-starting container makes every create-table call below
# fail with a connection error indistinguishable (once `mk` swallowed it)
# from "table already exists".
ready=0
for _ in $(seq 1 30); do
  if aws dynamodb list-tables --endpoint-url "$EP" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "dynamodb-local-tables.sh: DynamoDB Local at $EP did not become ready within 30s" >&2
  exit 1
fi

# Only tolerate "table already exists" (idempotent re-run); any other
# failure (bad endpoint, auth, malformed schema, ...) must fail loudly
# rather than being swallowed.
mk() {
  local err
  if err=$(aws dynamodb create-table --endpoint-url "$EP" --billing-mode PAY_PER_REQUEST "$@" 2>&1 >/dev/null); then
    return 0
  fi
  if grep -q "ResourceInUseException" <<<"$err"; then
    return 0
  fi
  echo "dynamodb-local-tables.sh: create-table failed: $err" >&2
  exit 1
}

mk --table-name credentials --attribute-definitions AttributeName=user_id,AttributeType=S AttributeName=username,AttributeType=S \
   --key-schema AttributeName=user_id,KeyType=HASH \
   --global-secondary-indexes '[{"IndexName":"username-index","KeySchema":[{"AttributeName":"username","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"}}]'
mk --table-name handles --attribute-definitions AttributeName=handle,AttributeType=S --key-schema AttributeName=handle,KeyType=HASH
mk --table-name device_bindings --attribute-definitions AttributeName=device_id,AttributeType=S --key-schema AttributeName=device_id,KeyType=HASH
mk --table-name identity_links --attribute-definitions AttributeName=link_pk,AttributeType=S --key-schema AttributeName=link_pk,KeyType=HASH
mk --table-name patreon_tokens --attribute-definitions AttributeName=user_id,AttributeType=S --key-schema AttributeName=user_id,KeyType=HASH
mk --table-name agent_delegations --attribute-definitions AttributeName=agent_did,AttributeType=S AttributeName=root_user_id,AttributeType=S \
   --key-schema AttributeName=agent_did,KeyType=HASH \
   --global-secondary-indexes '[{"IndexName":"root_user_id-index","KeySchema":[{"AttributeName":"root_user_id","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"}}]'
echo "tables ready at $EP"
