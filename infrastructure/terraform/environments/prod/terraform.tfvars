# Production Environment Configuration

environment = "prod"
aws_region  = "us-east-1"

# VPC
vpc_cidr = "10.0.0.0/16"

# RDS - production-ready
db_instance_class = "db.t3.micro"  # Upgrade to db.t3.small when traffic increases
db_name           = "coco_testai"
db_username       = "coco_admin"

# ElastiCache
redis_node_type = "cache.t3.micro"  # Upgrade to cache.t3.small when needed

# ECS - production settings
api_image         = "YOUR_AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/coco-api:latest"
api_cpu           = 512
api_memory        = 1024
api_desired_count = 2  # Two instances for high availability

# Domain (configure with your production domains)
api_domain_name      = ""  # e.g., "api.coco-testai.com"
frontend_domain_name = ""  # e.g., "app.coco-testai.com"
certificate_arn      = ""  # ACM certificate ARN for your domain
