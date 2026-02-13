# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Root Variables
# -----------------------------------------------------------------------------

variable "region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where all infrastructure will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the ECS services and ALB"
  type        = list(string)
}

variable "proxy_image" {
  description = "Docker image URI for the ShieldAI security proxy"
  type        = string
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

variable "cpu" {
  description = "CPU units for the Fargate task"
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

# --- WAF variables ---

variable "waf_block_mode" {
  description = "When true, WAF rules block requests; when false, count-only mode for testing"
  type        = bool
  default     = false
}

variable "auth_rate_limit" {
  description = "Max requests per 5-min window for auth endpoints (per IP)"
  type        = number
  default     = 500
}

variable "global_rate_limit" {
  description = "Max requests per 5-min window for all endpoints (per IP)"
  type        = number
  default     = 2000
}

variable "enable_bot_control" {
  description = "Enable AWS Bot Control managed rule group (premium, defaults to false)"
  type        = bool
  default     = false
}

variable "login_path_pattern" {
  description = "Path pattern to match auth endpoints for WAF rate limiting"
  type        = string
  default     = "/auth/"
}

# --- Security headers variables ---

variable "header_preset" {
  description = "Security header preset (strict, balanced, permissive)"
  type        = string
  default     = "balanced"
}

variable "csp_policy" {
  description = "Custom Content-Security-Policy header value (overrides preset CSP)"
  type        = string
  default     = ""
}

variable "permissions_policy" {
  description = "Custom Permissions-Policy header value"
  type        = string
  default     = "camera=(), microphone=(), geolocation=(self), payment=()"
}

# --- Secrets management variables ---

variable "secrets_rotation_days" {
  description = "Automatic rotation period for secrets in days (0 = disabled)"
  type        = number
  default     = 0
}

variable "secrets_rotation_lambda_arn" {
  description = "ARN of the Lambda function for secret rotation"
  type        = string
  default     = ""
}

variable "secrets_kms_deletion_window" {
  description = "KMS key deletion window in days (7-30)"
  type        = number
  default     = 14
}
