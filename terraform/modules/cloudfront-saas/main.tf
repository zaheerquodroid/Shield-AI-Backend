# -----------------------------------------------------------------------------
# ShieldAI — CloudFront SaaS Multi-Tenant Distribution
# Edge WAF + security headers + TLS 1.2+ for all tenants
# Architecture: Customer Domain → CloudFront → ALB → ECS Proxy → Upstream
# -----------------------------------------------------------------------------

locals {
  use_custom_cert = var.cloudfront_certificate_arn != ""
}

# CloudFront managed prefix list — for ALB SG origin protection
data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

# ---------------------------------------------------------------------------
# CloudFront Distribution
# ---------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "proxy" {
  # Fail-safe: prevent TLS 1.0 fallback in production.
  # Without a custom ACM cert, CloudFront forces minimum_protocol_version=TLSv1.
  # This lifecycle precondition blocks that dangerous silent downgrade.
  lifecycle {
    precondition {
      condition     = !(var.require_custom_cert_for_domains && length(var.customer_domains) > 0 && var.cloudfront_certificate_arn == "")
      error_message = "TLS DOWNGRADE RISK: customer_domains are set but no ACM certificate provided. CloudFront default cert only supports TLSv1 minimum. Provide cloudfront_certificate_arn to enforce TLSv1.2_2021, or set require_custom_cert_for_domains=false to acknowledge TLS 1.0 risk."
    }
  }

  comment             = "ShieldAI security proxy — ${var.environment}"
  enabled             = true
  is_ipv6_enabled     = true
  price_class         = var.price_class
  aliases             = var.customer_domains
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn
  http_version        = "http2and3"
  default_root_object = ""

  # --- Origin: ALB ---
  origin {
    domain_name = var.alb_dns_name
    origin_id   = "alb-origin"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_keepalive_timeout = 60
      origin_read_timeout      = 60
    }

    # Origin bypass prevention — secret header verified at ALB/proxy
    custom_header {
      name  = "X-ShieldAI-Origin-Verify"
      value = var.origin_verify_secret
    }
  }

  # --- Default Cache Behavior (no caching — pure proxy) ---
  default_cache_behavior {
    target_origin_id       = "alb-origin"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods  = ["GET", "HEAD"]

    # CachingDisabled — TTL=0, no caching to eliminate cache poisoning
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

    # AllViewer — preserves Host header for tenant routing
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3"

    # Security headers from security-headers module
    response_headers_policy_id = var.response_headers_policy_id
  }

  # --- Viewer Certificate ---
  viewer_certificate {
    acm_certificate_arn            = local.use_custom_cert ? var.cloudfront_certificate_arn : null
    ssl_support_method             = local.use_custom_cert ? "sni-only" : null
    minimum_protocol_version       = local.use_custom_cert ? "TLSv1.2_2021" : "TLSv1"
    cloudfront_default_certificate = local.use_custom_cert ? false : true
  }

  # --- Geo Restriction ---
  restrictions {
    geo_restriction {
      restriction_type = var.geo_restriction_type
      locations        = var.geo_restriction_locations
    }
  }

  # --- Access Logging (conditional) ---
  dynamic "logging_config" {
    for_each = var.enable_logging && var.log_bucket_domain_name != "" ? [1] : []

    content {
      bucket          = var.log_bucket_domain_name
      prefix          = "cloudfront/${var.environment}/"
      include_cookies = false
    }
  }

  tags = {
    Name        = "shieldai-cloudfront-${var.environment}"
    Environment = var.environment
    Project     = "shieldai"
    Module      = "cloudfront-saas"
    ManagedBy   = "terraform"
  }
}
