#!/bin/bash
# Start a stopped environment (test or demo)
# Usage: ./start-env.sh <environment>

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

echo "Starting $ENV environment..."

# Start RDS instance
echo "Starting RDS database..."
aws rds start-db-instance --db-instance-identifier "coco-${ENV}-db" 2>/dev/null || echo "RDS already running or doesn't exist"

# Wait for RDS to be available
echo "Waiting for RDS to be available..."
aws rds wait db-instance-available --db-instance-identifier "coco-${ENV}-db" 2>/dev/null || true

# Start ECS service (set desired count to 1)
echo "Starting ECS service..."
aws ecs update-service \
    --cluster "coco-${ENV}-cluster" \
    --service "coco-${ENV}-api" \
    --desired-count 1 \
    --no-cli-pager

# Wait for service to stabilize
echo "Waiting for ECS service to stabilize..."
aws ecs wait services-stable \
    --cluster "coco-${ENV}-cluster" \
    --services "coco-${ENV}-api"

echo ""
echo "✓ $ENV environment is now running!"
echo ""

# Get the ALB URL
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --names "coco-${ENV}-alb" \
    --query 'LoadBalancers[0].DNSName' \
    --output text 2>/dev/null || echo "")

if [[ -n "$ALB_DNS" ]]; then
    echo "API URL: http://${ALB_DNS}"
fi

# Get CloudFront URL
CF_ID=$(aws cloudfront list-distributions \
    --query "DistributionList.Items[?Comment=='Coco TestAI ${ENV} frontend'].Id" \
    --output text 2>/dev/null || echo "")

if [[ -n "$CF_ID" ]]; then
    CF_DOMAIN=$(aws cloudfront get-distribution --id "$CF_ID" \
        --query 'Distribution.DomainName' \
        --output text 2>/dev/null || echo "")
    echo "Frontend URL: https://${CF_DOMAIN}"
fi
