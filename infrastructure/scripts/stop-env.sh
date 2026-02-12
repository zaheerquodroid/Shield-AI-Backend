#!/bin/bash
# Stop an environment (test or demo) to save costs
# Usage: ./stop-env.sh <environment>

set -e

ENV=${1:-test}

if [[ "$ENV" == "prod" ]]; then
    echo "ERROR: Cannot start/stop prod environment with this script"
    exit 1
fi

if [[ "$ENV" != "test" && "$ENV" != "demo" ]]; then
    echo "ERROR: Environment must be 'test' or 'demo'"
    exit 1
fi

echo "Stopping $ENV environment..."

# Stop ECS service (set desired count to 0)
echo "Stopping ECS tasks..."
aws ecs update-service \
    --cluster "coco-${ENV}-cluster" \
    --service "coco-${ENV}-api" \
    --desired-count 0 \
    --no-cli-pager

# Stop RDS instance
echo "Stopping RDS database..."
aws rds stop-db-instance --db-instance-identifier "coco-${ENV}-db" 2>/dev/null || echo "RDS already stopped or doesn't exist"

echo ""
echo "✓ $ENV environment is now stopped!"
echo ""
echo "Cost savings while stopped:"
echo "  - ECS Fargate: ~\$0.50-\$0.80/day saved"
echo "  - RDS: ~\$0.50/day saved"
echo ""
echo "Note: RDS auto-restarts after 7 days. Re-run this script to stop again."
echo "Note: NAT Gateway, ALB, and ElastiCache still incur charges."
echo ""
echo "To fully eliminate costs, run: terraform destroy -var-file=environments/${ENV}/terraform.tfvars"
