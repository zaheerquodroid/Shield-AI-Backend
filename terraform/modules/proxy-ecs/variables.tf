# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — ECS Module Variables
# -----------------------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID where the proxy infrastructure will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the ECS service and ALB"
  type        = list(string)
}

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "proxy_image" {
  description = "Docker image URI for the ShieldAI security proxy"
  type        = string
}

variable "cpu" {
  description = "CPU units for the Fargate task (1 vCPU = 1024)"
  type        = number
  default     = 256
}

variable "memory" {
  description = "Memory in MiB for the Fargate task"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 1
}

variable "min_count" {
  description = "Minimum number of ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

variable "max_count" {
  description = "Maximum number of ECS tasks for auto-scaling"
  type        = number
  default     = 10
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS on the ALB"
  type        = string
}

variable "redis_url_ssm_arn" {
  description = "SSM Parameter Store ARN for Redis URL"
  type        = string
}

variable "postgres_url_ssm_arn" {
  description = "SSM Parameter Store ARN for PostgreSQL URL"
  type        = string
}

variable "api_key_ssm_arn" {
  description = "SSM Parameter Store ARN for API key"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group name for proxy container logs"
  type        = string
  default     = "/ecs/shieldai-proxy"
}

variable "alb_access_logs_bucket" {
  description = "S3 bucket name for ALB access logs"
  type        = string
  default     = ""
}

variable "enable_alb_access_logs" {
  description = "Enable ALB access logging"
  type        = bool
  default     = false
}

# --- CloudFront origin protection ---

variable "restrict_to_cloudfront" {
  description = "When true, ALB only accepts traffic from CloudFront (origin bypass prevention)"
  type        = bool
  default     = false
}

variable "origin_verify_secret" {
  description = "Shared secret for X-ShieldAI-Origin-Verify header verification"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cloudfront_prefix_list_id" {
  description = "AWS managed prefix list ID for CloudFront IP ranges"
  type        = string
  default     = ""
}
