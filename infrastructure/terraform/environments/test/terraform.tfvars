# Test Environment Configuration

environment = "test"
aws_region  = "us-east-1"

# VPC
vpc_cidr = "10.1.0.0/16"

# RDS - smallest for test
db_instance_class = "db.t3.micro"
db_name           = "coco_testai"
db_username       = "coco_admin"

# ElastiCache - smallest for test
redis_node_type = "cache.t3.micro"

# ECS - minimal resources for test
# Starts with 0 tasks - use start-env.sh or GitHub Actions to spin up
api_image         = "YOUR_AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/coco-api:latest"
api_cpu           = 256
api_memory        = 512
api_desired_count = 0  # On-demand: start with ./scripts/start-env.sh test

# Domain (optional - leave empty for ALB/CloudFront URLs)
api_domain_name      = ""
frontend_domain_name = ""
certificate_arn      = ""
