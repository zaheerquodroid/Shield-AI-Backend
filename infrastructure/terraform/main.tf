# Coco TestAI - Main Terraform Configuration
# Supports test, demo, and prod environments

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state - uncomment and configure for team use
  # backend "s3" {
  #   bucket         = "coco-testai-terraform-state"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "coco-testai-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "coco-testai"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}

# RDS PostgreSQL
module "rds" {
  source = "./modules/rds"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  db_instance_class  = var.db_instance_class
  db_name            = var.db_name
  db_username        = var.db_username

  depends_on = [module.vpc]
}

# ElastiCache Redis
module "elasticache" {
  source = "./modules/elasticache"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_type          = var.redis_node_type

  depends_on = [module.vpc]
}

# ECS Fargate for API
module "ecs" {
  source = "./modules/ecs"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  public_subnet_ids  = module.vpc.public_subnet_ids
  private_subnet_ids = module.vpc.private_subnet_ids

  api_image          = var.api_image
  api_cpu            = var.api_cpu
  api_memory         = var.api_memory
  api_desired_count  = var.api_desired_count

  db_host            = module.rds.db_endpoint
  db_name            = var.db_name
  db_username        = var.db_username
  db_password_arn    = module.rds.db_password_secret_arn

  redis_host         = module.elasticache.redis_endpoint

  domain_name        = var.api_domain_name
  certificate_arn    = var.certificate_arn

  depends_on = [module.vpc, module.rds, module.elasticache]
}

# Frontend (S3 + CloudFront)
module "frontend" {
  source = "./modules/frontend"

  environment     = var.environment
  domain_name     = var.frontend_domain_name
  certificate_arn = var.certificate_arn
  api_origin      = module.ecs.alb_dns_name
}

# Outputs
output "api_url" {
  description = "API endpoint URL"
  value       = module.ecs.api_url
}

output "frontend_url" {
  description = "Frontend CloudFront URL"
  value       = module.frontend.cloudfront_url
}

output "frontend_bucket" {
  description = "Frontend S3 bucket name"
  value       = module.frontend.bucket_name
}

output "db_endpoint" {
  description = "RDS database endpoint"
  value       = module.rds.db_endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = module.elasticache.redis_endpoint
  sensitive   = true
}
