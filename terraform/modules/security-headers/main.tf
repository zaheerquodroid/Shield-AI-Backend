# -----------------------------------------------------------------------------
# ShieldAI — CloudFront Response Headers Policy
# Applies security headers at the CDN edge
# -----------------------------------------------------------------------------

locals {
  presets = {
    strict = {
      hsts_max_age         = 63072000
      hsts_include_sub     = true
      hsts_preload         = true
      frame_option         = "DENY"
      referrer_policy      = "no-referrer"
      csp                  = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
      permissions          = "camera=(), microphone=(), geolocation=(), payment=()"
    }
    balanced = {
      hsts_max_age         = 31536000
      hsts_include_sub     = true
      hsts_preload         = false
      frame_option         = "SAMEORIGIN"
      referrer_policy      = "strict-origin-when-cross-origin"
      csp                  = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'"
      permissions          = "camera=(), microphone=(), geolocation=(self), payment=()"
    }
    permissive = {
      hsts_max_age         = 31536000
      hsts_include_sub     = false
      hsts_preload         = false
      frame_option         = "SAMEORIGIN"
      referrer_policy      = "strict-origin-when-cross-origin"
      csp                  = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src * data:; font-src * data:; connect-src *; frame-ancestors 'self' https:; form-action 'self' https:; base-uri 'self'; object-src 'none'"
      permissions          = "camera=(self), microphone=(self), geolocation=(self), payment=(self)"
    }
  }

  selected = local.presets[var.header_preset]

  # Use custom CSP if provided, otherwise use preset
  effective_csp         = var.csp_policy != "" ? var.csp_policy : local.selected.csp
  effective_permissions = var.permissions_policy != "" ? var.permissions_policy : local.selected.permissions
}

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "shieldai-security-headers-${var.environment}"
  comment = "ShieldAI security headers — ${var.header_preset} preset (${var.environment})"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = local.selected.hsts_max_age
      include_subdomains         = local.selected.hsts_include_sub
      preload                    = local.selected.hsts_preload
      override                   = true
    }

    content_security_policy {
      content_security_policy = local.effective_csp
      override                = true
    }

    frame_options {
      frame_option = local.selected.frame_option
      override     = true
    }

    content_type_options {
      override = true
    }

    referrer_policy {
      referrer_policy = local.selected.referrer_policy
      override        = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = local.effective_permissions
      override = true
    }
  }

  # Remove server identification headers
  remove_headers_config {
    items {
      header = "Server"
    }
    items {
      header = "X-Powered-By"
    }
  }

  tags = {
    Environment = var.environment
    Project     = "shieldai"
    Module      = "security-headers"
  }
}
