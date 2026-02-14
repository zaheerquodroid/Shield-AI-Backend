# -----------------------------------------------------------------------------
# ShieldAI — CloudFront WAF WebACL (CLOUDFRONT scope)
# Defense-in-depth: edge WAF in addition to existing REGIONAL WAF at ALB
# Adds body-size-limit rule to prevent WAF inspection bypass (8KB limit)
#
# IMPORTANT: CLOUDFRONT-scoped WAF must be created in us-east-1.
# The calling module's provider must be in us-east-1 or use a provider alias.
# The root module validates this via the enable_cloudfront + region check.
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "cloudfront" {
  name        = "shieldai-cloudfront-waf-${var.environment}"
  description = "ShieldAI CloudFront WAF — ${var.environment}"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # --- Body Size Limit (priority 5) ---
  # Prevents WAF inspection bypass via oversized request bodies (>8KB)
  rule {
    name     = "body-size-limit"
    priority = 5

    action {
      dynamic "block" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 8192

        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-body-limit-${var.environment}"
    }
  }

  # --- AWS Managed Rule: Common Rule Set (priority 10) ---
  rule {
    name     = "aws-common-rules"
    priority = 10

    override_action {
      dynamic "none" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-common-rules-${var.environment}"
    }
  }

  # --- AWS Managed Rule: SQL Injection (priority 20) ---
  rule {
    name     = "aws-sqli-rules"
    priority = 20

    override_action {
      dynamic "none" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-sqli-rules-${var.environment}"
    }
  }

  # --- AWS Managed Rule: Known Bad Inputs (priority 30) ---
  rule {
    name     = "aws-known-bad-inputs"
    priority = 30

    override_action {
      dynamic "none" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-bad-inputs-${var.environment}"
    }
  }

  # --- Auth Endpoint Rate Limit (priority 40) ---
  rule {
    name     = "auth-rate-limit"
    priority = 40

    action {
      dynamic "block" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.auth_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = var.login_path_pattern
            positional_constraint = "CONTAINS"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-auth-rate-${var.environment}"
    }
  }

  # --- Global Rate Limit (priority 50) ---
  rule {
    name     = "global-rate-limit"
    priority = 50

    action {
      dynamic "block" {
        for_each = var.waf_block_mode ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.waf_block_mode ? [] : [1]
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.global_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "shieldai-cf-global-rate-${var.environment}"
    }
  }

  # --- Optional: Bot Control (priority 60) ---
  dynamic "rule" {
    for_each = var.enable_bot_control ? [1] : []

    content {
      name     = "aws-bot-control"
      priority = 60

      override_action {
        dynamic "none" {
          for_each = var.waf_block_mode ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.waf_block_mode ? [] : [1]
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesBotControlRuleSet"
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "shieldai-cf-bot-control-${var.environment}"
      }
    }
  }

  # --- WebACL-level visibility ---
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "shieldai-cf-waf-${var.environment}"
  }

  tags = {
    Environment = var.environment
    Project     = "shieldai"
    Module      = "cloudfront-saas"
    ManagedBy   = "terraform"
  }
}
