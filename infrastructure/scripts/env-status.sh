#!/bin/bash
# Check status of all environments
# Usage: ./env-status.sh

echo "Coco TestAI Environment Status"
echo "==============================="
echo ""

for ENV in test demo prod; do
    echo "[$ENV]"

    # ECS status
    ECS_COUNT=$(aws ecs describe-services \
        --cluster "coco-${ENV}-cluster" \
        --services "coco-${ENV}-api" \
        --query 'services[0].runningCount' \
        --output text 2>/dev/null || echo "N/A")

    if [[ "$ECS_COUNT" == "N/A" ]]; then
        echo "  ECS: Not deployed"
    elif [[ "$ECS_COUNT" == "0" ]]; then
        echo "  ECS: Stopped (0 tasks)"
    else
        echo "  ECS: Running ($ECS_COUNT tasks)"
    fi

    # RDS status
    RDS_STATUS=$(aws rds describe-db-instances \
        --db-instance-identifier "coco-${ENV}-db" \
        --query 'DBInstances[0].DBInstanceStatus' \
        --output text 2>/dev/null || echo "N/A")

    if [[ "$RDS_STATUS" == "N/A" ]]; then
        echo "  RDS: Not deployed"
    else
        echo "  RDS: $RDS_STATUS"
    fi

    # Redis status
    REDIS_STATUS=$(aws elasticache describe-cache-clusters \
        --cache-cluster-id "coco-${ENV}-redis" \
        --query 'CacheClusters[0].CacheClusterStatus' \
        --output text 2>/dev/null || echo "N/A")

    if [[ "$REDIS_STATUS" == "N/A" ]]; then
        echo "  Redis: Not deployed"
    else
        echo "  Redis: $REDIS_STATUS"
    fi

    echo ""
done
