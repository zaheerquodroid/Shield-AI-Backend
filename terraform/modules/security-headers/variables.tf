# -----------------------------------------------------------------------------
# ShieldAI — Security Headers Module Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "header_preset" {
  description = "Header preset profile: strict, balanced, or permissive"
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

variable "permissions_policy" {
  description = "Custom Permissions-Policy header value"
  type        = string
  default     = ""
}
