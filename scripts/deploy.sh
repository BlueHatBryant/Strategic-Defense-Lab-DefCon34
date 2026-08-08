#!/usr/bin/env bash
set -euo pipefail

region="${1:-}"
stack_name="${2:-defcon34-strategic-defense}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${script_dir}/../infra/template.yaml"

if [[ -z "${region}" ]]; then
  echo "Usage: $0 <region> [stack-name]" >&2
  exit 2
fi

cat <<EOF
This will create a KMS key, encrypted CloudWatch log group, and Bedrock Guardrail
in account/region shown below. It may incur charges. The vulnerable IAM policy is
NOT deployed. Use a dedicated sandbox and run cleanup when finished.
EOF

aws sts get-caller-identity --output table
aws cloudformation validate-template \
  --template-body "file://${template}" \
  --region "${region}" >/dev/null

read -r -p "Type DEPLOY to continue: " confirmation
if [[ "${confirmation}" != "DEPLOY" ]]; then
  echo "Deployment cancelled."
  exit 1
fi

aws cloudformation deploy \
  --stack-name "${stack_name}" \
  --template-file "${template}" \
  --region "${region}" \
  --parameter-overrides ResourcePrefix=defcon34-strategic-defense \
  --tags Workshop=DEFCON34 DataClassification=SyntheticOnly

aws cloudformation describe-stacks \
  --stack-name "${stack_name}" \
  --region "${region}" \
  --query 'Stacks[0].Outputs' \
  --output table
