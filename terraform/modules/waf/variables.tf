# -----------------------------------------------------------------------------
# ShieldAI — WAF Module Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "waf_block_mode" {
  description = "When true, WAF rules block requests; when false, count-only mode"
  type        = bool
  default     = false
}

variable "scope" {
  description = "WAF scope: REGIONAL for ALB, CLOUDFRONT for distributions"
  type        = string
  default     = "REGIONAL"
}

variable "alb_arn" {
  description = "ARN of the ALB to associate with the WAF WebACL"
  type        = string
  default     = ""
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
  description = "Enable AWS Bot Control managed rule group (premium)"
  type        = bool
  default     = false
}

variable "login_path_pattern" {
  description = "Path pattern to match auth endpoints for rate limiting"
  type        = string
  default     = "/auth/"
}
