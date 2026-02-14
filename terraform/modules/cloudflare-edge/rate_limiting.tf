# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — Rate Limiting
#
# Custom rate limiting rulesets (phase: http_ratelimit):
# 1. Auth endpoint rate limit — /auth/ and /login paths
# 2. API endpoint rate limit — /api/ paths
# 3. Global rate limit — all requests
#
# Thresholds configurable via variables. Action: block with 429 response.
# In "log" mode, action is "log" instead of "block".
# -----------------------------------------------------------------------------

locals {
  rate_action = var.waf_mode == "block" ? "block" : "log"
}

resource "cloudflare_ruleset" "rate_limiting" {
  zone_id     = var.zone_id
  name        = "ShieldAI Rate Limiting — ${var.environment}"
  description = "Custom rate limiting rules for ShieldAI edge security"
  kind        = "zone"
  phase       = "http_ratelimit"

  # --- Auth Endpoint Rate Limit ---
  rules {
    action      = local.rate_action
    expression  = "(http.request.uri.path contains \"${var.login_path_pattern}\" or http.request.uri.path contains \"/login\")"
    description = "Auth endpoint rate limit: ${var.auth_rate_limit} req/min per IP"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = var.auth_rate_limit
      mitigation_timeout  = 60
    }
  }

  # --- API Endpoint Rate Limit ---
  rules {
    action      = local.rate_action
    expression  = "(http.request.uri.path contains \"/api/\")"
    description = "API endpoint rate limit: ${var.api_rate_limit} req/min per IP"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = var.api_rate_limit
      mitigation_timeout  = 60
    }
  }

  # --- Global Rate Limit ---
  rules {
    action      = local.rate_action
    expression  = "true"
    description = "Global rate limit: ${var.global_rate_limit} req/min per IP"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = var.global_rate_limit
      mitigation_timeout  = 60
    }
  }
}
