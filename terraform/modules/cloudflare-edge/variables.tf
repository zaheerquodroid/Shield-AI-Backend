# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — Variables
# -----------------------------------------------------------------------------

variable "zone_id" {
  description = "Cloudflare zone ID for the customer domain"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character hex Cloudflare zone ID"
  }
}

variable "environment" {
  description = "Deployment environment (test, demo, staging, prod)"
  type        = string

  validation {
    condition     = contains(["test", "demo", "staging", "prod"], var.environment)
    error_message = "environment must be one of: test, demo, staging, prod"
  }
}

variable "domain" {
  description = "Customer domain name (e.g. app.example.com)"
  type        = string

  validation {
    condition     = length(var.domain) > 0 && can(regex("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", var.domain))
    error_message = "domain must be a valid non-empty domain name"
  }
}

variable "origin" {
  description = "Origin server address — security proxy ALB DNS or app origin"
  type        = string

  validation {
    condition     = length(var.origin) > 0
    error_message = "origin must not be empty"
  }
}

# --- WAF ---

variable "waf_mode" {
  description = "WAF action mode: 'block' for production, 'log' for testing"
  type        = string
  default     = "log"

  validation {
    condition     = contains(["block", "log"], var.waf_mode)
    error_message = "waf_mode must be 'block' or 'log'"
  }
}

variable "enable_owasp_ruleset" {
  description = "Enable OWASP Core Ruleset (Cloudflare managed)"
  type        = bool
  default     = true
}

variable "enable_credentials_check" {
  description = "Enable Exposed Credentials Check managed ruleset"
  type        = bool
  default     = true
}

# --- Rate Limiting ---

variable "auth_rate_limit" {
  description = "Requests per minute per IP for auth endpoints (/auth/ or /login)"
  type        = number
  default     = 20

  validation {
    condition     = var.auth_rate_limit > 0 && var.auth_rate_limit <= 10000
    error_message = "auth_rate_limit must be between 1 and 10000"
  }
}

variable "api_rate_limit" {
  description = "Requests per minute per IP for API endpoints (/api/)"
  type        = number
  default     = 100

  validation {
    condition     = var.api_rate_limit > 0 && var.api_rate_limit <= 100000
    error_message = "api_rate_limit must be between 1 and 100000"
  }
}

variable "global_rate_limit" {
  description = "Requests per minute per IP for all endpoints"
  type        = number
  default     = 500

  validation {
    condition     = var.global_rate_limit > 0 && var.global_rate_limit <= 100000
    error_message = "global_rate_limit must be between 1 and 100000"
  }
}

variable "login_path_pattern" {
  description = "URI path pattern for auth rate limiting (simple path, no special chars)"
  type        = string
  default     = "/auth/"

  validation {
    condition     = can(regex("^/[a-zA-Z0-9/_-]+/?$", var.login_path_pattern))
    error_message = "login_path_pattern must be a simple URI path (e.g. /auth/) — no quotes, parentheses, or special characters"
  }
}

# --- Security Headers ---

variable "header_preset" {
  description = "Security header preset: strict, balanced, or permissive"
  type        = string
  default     = "balanced"

  validation {
    condition     = contains(["strict", "balanced", "permissive"], var.header_preset)
    error_message = "header_preset must be one of: strict, balanced, permissive"
  }
}

variable "csp_policy" {
  description = "Custom Content-Security-Policy (overrides preset CSP if non-empty)"
  type        = string
  default     = ""
}

# --- Zone Settings ---

variable "ssl_mode" {
  description = "Cloudflare SSL mode — only 'strict' (validates origin cert) or 'full' (accepts any origin cert) are allowed"
  type        = string
  default     = "strict"

  validation {
    condition     = contains(["strict", "full"], var.ssl_mode)
    error_message = "ssl_mode must be 'strict' or 'full' — 'flexible' and 'off' are insecure (plaintext to origin)"
  }
}

variable "min_tls_version" {
  description = "Minimum TLS version — only 1.2 and 1.3 are allowed (TLS 1.0/1.1 deprecated per RFC 8996)"
  type        = string
  default     = "1.2"

  validation {
    condition     = contains(["1.2", "1.3"], var.min_tls_version)
    error_message = "min_tls_version must be '1.2' or '1.3' — TLS 1.0 and 1.1 are deprecated (RFC 8996, PCI DSS 3.2.1)"
  }
}

variable "always_use_https" {
  description = "Redirect all HTTP requests to HTTPS"
  type        = bool
  default     = true
}

variable "enable_bot_fight_mode" {
  description = "Enable Cloudflare Bot Fight Mode"
  type        = bool
  default     = true
}

variable "security_level" {
  description = "Cloudflare security level (low, medium, high, under_attack)"
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["low", "medium", "high", "under_attack"], var.security_level)
    error_message = "security_level must be one of: low, medium, high, under_attack — 'off' and 'essentially_off' are insecure"
  }
}

# --- DNS ---

variable "dns_proxied" {
  description = "Whether DNS record is proxied through Cloudflare (orange cloud)"
  type        = bool
  default     = true
}
