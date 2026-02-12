# Coco TestAI - Terraform Variables

variable "environment" {
  description = "Environment name (test, demo, prod)"
  type        = string

  validation {
    condition     = contains(["test", "demo", "prod"], var.environment)
    error_message = "Environment must be test, demo, or prod."
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# VPC
variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

# RDS
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "coco_testai"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "coco_admin"
}

# ElastiCache
variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

# ECS
variable "api_image" {
  description = "Docker image for API"
  type        = string
}

variable "api_cpu" {
  description = "CPU units for API task (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memory for API task in MB"
  type        = number
  default     = 1024
}

variable "api_desired_count" {
  description = "Number of API task instances"
  type        = number
  default     = 1
}

# Domain & SSL
variable "api_domain_name" {
  description = "Domain name for API (e.g., api.coco-testai.com)"
  type        = string
  default     = ""
}

variable "frontend_domain_name" {
  description = "Domain name for frontend (e.g., app.coco-testai.com)"
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  type        = string
  default     = ""
}
