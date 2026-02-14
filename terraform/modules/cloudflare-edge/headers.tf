# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — Security Headers
#
# Response Header Modification Transform Rules inject security headers into
# all responses. Three presets (strict, balanced, permissive) provide
# graduated security postures. Removes Server and X-Powered-By headers.
#
# Equivalent to CloudFront security-headers module for Cloudflare CDN.
# -----------------------------------------------------------------------------

locals {
  presets = {
    strict = {
      hsts               = "max-age=63072000; includeSubDomains; preload"
      csp                = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
      x_frame_options    = "DENY"
      referrer_policy    = "no-referrer"
      permissions_policy = "camera=(), microphone=(), geolocation=(), payment=()"
    }
    balanced = {
      hsts               = "max-age=31536000; includeSubDomains"
      csp                = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'"
      x_frame_options    = "SAMEORIGIN"
      referrer_policy    = "strict-origin-when-cross-origin"
      permissions_policy = "camera=(), microphone=(), geolocation=(self), payment=()"
    }
    permissive = {
      hsts               = "max-age=31536000"
      csp                = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src * data:; font-src * data:; connect-src *; frame-ancestors 'self' https:; form-action 'self' https:; base-uri 'self'; object-src 'none'"
      x_frame_options    = "SAMEORIGIN"
      referrer_policy    = "strict-origin-when-cross-origin"
      permissions_policy = "camera=(self), microphone=(self), geolocation=(self), payment=(self)"
    }
  }

  selected = local.presets[var.header_preset]

  effective_csp = var.csp_policy != "" ? var.csp_policy : local.selected.csp
}

resource "cloudflare_ruleset" "security_headers" {
  zone_id     = var.zone_id
  name        = "ShieldAI Security Headers — ${var.environment}"
  description = "Inject security headers into all responses — ${var.header_preset} preset"
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules {
    action      = "rewrite"
    expression  = "true"
    description = "Inject security headers and remove server fingerprints"
    enabled     = true

    action_parameters {
      headers {
        name      = "Strict-Transport-Security"
        operation = "set"
        value     = local.selected.hsts
      }
      headers {
        name      = "Content-Security-Policy"
        operation = "set"
        value     = local.effective_csp
      }
      headers {
        name      = "X-Frame-Options"
        operation = "set"
        value     = local.selected.x_frame_options
      }
      headers {
        name      = "X-Content-Type-Options"
        operation = "set"
        value     = "nosniff"
      }
      headers {
        name      = "Referrer-Policy"
        operation = "set"
        value     = local.selected.referrer_policy
      }
      headers {
        name      = "Permissions-Policy"
        operation = "set"
        value     = local.selected.permissions_policy
      }
      headers {
        name      = "X-XSS-Protection"
        operation = "set"
        value     = "0"
      }
      headers {
        name      = "Server"
        operation = "remove"
      }
      headers {
        name      = "X-Powered-By"
        operation = "remove"
      }
    }
  }
}
