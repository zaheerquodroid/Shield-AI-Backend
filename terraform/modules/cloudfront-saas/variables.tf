# -----------------------------------------------------------------------------
# ShieldAI — CloudFront SaaS Distribution Module Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the ALB origin (from proxy-ecs module)"
  type        = string
}

variable "response_headers_policy_id" {
  description = "CloudFront response headers policy ID (from security-headers module)"
  type        = string
}

variable "origin_verify_secret" {
  description = "Shared secret for X-ShieldAI-Origin-Verify header (origin bypass prevention)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.origin_verify_secret) >= 32
    error_message = "origin_verify_secret must be at least 32 characters for security."
  }
}

variable "cloudfront_certificate_arn" {
  description = "ACM certificate ARN in us-east-1 for custom domains (empty = default CloudFront cert)"
  type        = string
  default     = ""

  # NOTE: When empty, CloudFront uses its default *.cloudfront.net cert.
  # AWS limitation: default cert forces TLS minimum to TLSv1 (not configurable).
  # TLSv1.2_2021 enforcement only works with a custom ACM certificate.
  # The require_custom_cert_for_domains variable below guards against this.
}

variable "require_custom_cert_for_domains" {
  description = "When true, fail if customer_domains are set but no ACM cert is provided (prevents TLS 1.0 fallback in production)"
  type        = bool
  default     = true
}

variable "customer_domains" {
  description = "List of tenant custom domain aliases for the distribution"
  type        = list(string)
  default     = []
}

variable "price_class" {
  description = "CloudFront price class (PriceClass_100=US/CA/EU, PriceClass_200=+Asia, PriceClass_All=global)"
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.price_class)
    error_message = "price_class must be one of: PriceClass_100, PriceClass_200, PriceClass_All."
  }
}

variable "geo_restriction_type" {
  description = "Geo restriction type (none, whitelist, blacklist)"
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "whitelist", "blacklist"], var.geo_restriction_type)
    error_message = "geo_restriction_type must be one of: none, whitelist, blacklist."
  }
}

variable "geo_restriction_locations" {
  description = "List of ISO 3166-1 alpha-2 country codes for geo restriction"
  type        = list(string)
  default     = []
}

variable "waf_block_mode" {
  description = "When true, WAF rules block requests; when false, count-only mode"
  type        = bool
  default     = false
}

variable "enable_bot_control" {
  description = "Enable AWS Bot Control managed rule group (premium)"
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

variable "login_path_pattern" {
  description = "Path pattern to match auth endpoints for WAF rate limiting"
  type        = string
  default     = "/auth/"
}

variable "enable_logging" {
  description = "Enable CloudFront access logging to S3"
  type        = bool
  default     = true
}

variable "log_bucket_domain_name" {
  description = "S3 bucket domain name for CloudFront access logs (required when enable_logging=true)"
  type        = string
  default     = ""
}
