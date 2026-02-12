# Demo Environment Configuration

environment = "demo"
aws_region  = "us-east-1"

# VPC
vpc_cidr = "10.2.0.0/16"

# RDS - small but performant for demos
db_instance_class = "db.t3.micro"
db_name           = "coco_testai"
db_username       = "coco_admin"

# ElastiCache
redis_node_type = "cache.t3.micro"

# ECS - slightly more resources for smooth demos
# Starts with 0 tasks - use start-env.sh or GitHub Actions to spin up
api_image         = "YOUR_AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/coco-api:latest"
api_cpu           = 512
api_memory        = 1024
api_desired_count = 0  # On-demand: start with ./scripts/start-env.sh demo

# Domain (optional - add your demo domain)
api_domain_name      = ""
frontend_domain_name = ""
certificate_arn      = ""
