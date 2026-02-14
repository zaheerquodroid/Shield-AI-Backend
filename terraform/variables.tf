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

# --- CloudFront variables ---

variable "enable_cloudfront" {
  description = "Enable CloudFront distribution in front of ALB (opt-in)"
  type        = bool
  default     = false
}

variable "cloudfront_origin_verify_secret" {
  description = "Shared secret for X-ShieldAI-Origin-Verify header (origin bypass prevention)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "cloudfront_certificate_arn" {
  description = "ACM certificate ARN in us-east-1 for CloudFront custom domains"
  type        = string
  default     = ""
}

variable "customer_domains" {
  description = "List of tenant custom domain aliases for CloudFront"
  type        = list(string)
  default     = []
}

variable "cloudfront_price_class" {
  description = "CloudFront price class (PriceClass_100, PriceClass_200, PriceClass_All)"
  type        = string
  default     = "PriceClass_100"
}

variable "cloudfront_geo_restriction_type" {
  description = "CloudFront geo restriction type (none, whitelist, blacklist)"
  type        = string
  default     = "none"
}

variable "cloudfront_geo_restriction_locations" {
  description = "ISO 3166-1 alpha-2 country codes for CloudFront geo restriction"
  type        = list(string)
  default     = []
}

variable "cloudfront_enable_logging" {
  description = "Enable CloudFront access logging to S3"
  type        = bool
  default     = true
}

variable "cloudfront_log_bucket" {
  description = "S3 bucket domain name for CloudFront access logs"
  type        = string
  default     = ""
}

# --- Cloudflare edge variables ---

variable "enable_cloudflare" {
  description = "Enable Cloudflare edge security module (alternative to CloudFront)"
  type        = bool
  default     = false
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for the customer domain"
  type        = string
  default     = ""
}

variable "cloudflare_domain" {
  description = "Customer domain name to protect via Cloudflare"
  type        = string
  default     = ""
}

variable "cloudflare_origin" {
  description = "Origin server address (defaults to ALB DNS name if empty)"
  type        = string
  default     = ""
}

variable "cloudflare_enable_owasp" {
  description = "Enable OWASP Core Ruleset on Cloudflare WAF"
  type        = bool
  default     = true
}

variable "cloudflare_enable_credentials_check" {
  description = "Enable Exposed Credentials Check on Cloudflare WAF"
  type        = bool
  default     = true
}

variable "cloudflare_auth_rate_limit" {
  description = "Cloudflare auth endpoint rate limit (requests per minute per IP)"
  type        = number
  default     = 20

  validation {
    condition     = var.cloudflare_auth_rate_limit > 0 && var.cloudflare_auth_rate_limit <= 10000
    error_message = "cloudflare_auth_rate_limit must be between 1 and 10000"
  }
}

variable "cloudflare_api_rate_limit" {
  description = "Cloudflare API endpoint rate limit (requests per minute per IP)"
  type        = number
  default     = 100

  validation {
    condition     = var.cloudflare_api_rate_limit > 0 && var.cloudflare_api_rate_limit <= 100000
    error_message = "cloudflare_api_rate_limit must be between 1 and 100000"
  }
}

variable "cloudflare_global_rate_limit" {
  description = "Cloudflare global rate limit (requests per minute per IP)"
  type        = number
  default     = 500

  validation {
    condition     = var.cloudflare_global_rate_limit > 0 && var.cloudflare_global_rate_limit <= 100000
    error_message = "cloudflare_global_rate_limit must be between 1 and 100000"
  }
}

variable "cloudflare_ssl_mode" {
  description = "Cloudflare SSL mode — only 'strict' or 'full' allowed"
  type        = string
  default     = "strict"

  validation {
    condition     = contains(["strict", "full"], var.cloudflare_ssl_mode)
    error_message = "cloudflare_ssl_mode must be 'strict' or 'full' — 'flexible' and 'off' are insecure"
  }
}

variable "cloudflare_min_tls_version" {
  description = "Cloudflare minimum TLS version — only 1.2+ allowed"
  type        = string
  default     = "1.2"

  validation {
    condition     = contains(["1.2", "1.3"], var.cloudflare_min_tls_version)
    error_message = "cloudflare_min_tls_version must be '1.2' or '1.3' — TLS 1.0/1.1 are deprecated"
  }
}

variable "cloudflare_always_use_https" {
  description = "Cloudflare always redirect HTTP to HTTPS"
  type        = bool
  default     = true
}

variable "cloudflare_enable_bot_fight_mode" {
  description = "Enable Cloudflare Bot Fight Mode"
  type        = bool
  default     = true
}

variable "cloudflare_security_level" {
  description = "Cloudflare security level (low, medium, high, under_attack)"
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["low", "medium", "high", "under_attack"], var.cloudflare_security_level)
    error_message = "cloudflare_security_level must be one of: low, medium, high, under_attack"
  }
}

variable "cloudflare_dns_proxied" {
  description = "Whether Cloudflare DNS record is proxied (orange cloud)"
  type        = bool
  default     = true
}
