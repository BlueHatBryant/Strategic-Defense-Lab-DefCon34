#!/usr/bin/env bash
set -euo pipefail

region="${1:-}"
stack_name="${2:-defcon34-strategic-defense}"

if [[ -z "${region}" ]]; then
  echo "Usage: CONFIRM_DELETE=<stack-name> $0 <region> [stack-name]" >&2
  exit 2
fi

if [[ "${CONFIRM_DELETE:-}" != "${stack_name}" ]]; then
  cat >&2 <<EOF
Cleanup deletes the CloudFormation stack '${stack_name}' in '${region}'.
The KMS key will enter its configured 7-day pending-deletion period.
To confirm, run:
  CONFIRM_DELETE=${stack_name} $0 ${region} ${stack_name}
EOF
  exit 2
fi

aws cloudformation describe-stacks \
  --stack-name "${stack_name}" \
  --region "${region}" \
  --query 'Stacks[0].{Name:StackName,Status:StackStatus}'

aws cloudformation delete-stack \
  --stack-name "${stack_name}" \
  --region "${region}"

aws cloudformation wait stack-delete-complete \
  --stack-name "${stack_name}" \
  --region "${region}"

echo "Deleted stack ${stack_name}. Check KMS for the scheduled key deletion."
