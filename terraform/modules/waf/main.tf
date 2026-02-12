# -----------------------------------------------------------------------------
# ShieldAI — AWS WAF WebACL Module
# Managed rulesets, rate-based rules, optional Bot Control
# -----------------------------------------------------------------------------

locals {
  action = var.waf_block_mode ? "block" : "count"
}

resource "aws_wafv2_web_acl" "main" {
  name        = "shieldai-waf-${var.environment}"
  description = "ShieldAI WAF — ${var.environment}"
  scope       = var.scope

  default_action {
    allow {}
  }

  # --- AWS Managed Rule: Common Rule Set ---
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
      metric_name                = "shieldai-common-rules-${var.environment}"
    }
  }

  # --- AWS Managed Rule: SQL Injection ---
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
      metric_name                = "shieldai-sqli-rules-${var.environment}"
    }
  }

  # --- AWS Managed Rule: Known Bad Inputs ---
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
      metric_name                = "shieldai-bad-inputs-${var.environment}"
    }
  }

  # --- Auth Endpoint Rate Limit ---
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
      metric_name                = "shieldai-auth-rate-${var.environment}"
    }
  }

  # --- Global Rate Limit ---
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
      metric_name                = "shieldai-global-rate-${var.environment}"
    }
  }

  # --- Optional: Bot Control ---
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
        metric_name                = "shieldai-bot-control-${var.environment}"
      }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "shieldai-waf-${var.environment}"
  }

  tags = {
    Environment = var.environment
    Project     = "shieldai"
    Module      = "waf"
  }
}

# --- ALB Association ---
resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.alb_arn != "" ? 1 : 0
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
