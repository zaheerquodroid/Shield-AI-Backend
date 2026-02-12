# -----------------------------------------------------------------------------
# ShieldAI — WAF CloudWatch Dashboard
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "shieldai-waf-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "WAF — Blocked vs Allowed"
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "ALL"],
            ["AWS/WAFV2", "AllowedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "ALL"],
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Rate Limit Hits"
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "auth-rate-limit"],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "global-rate-limit"],
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Managed Rule Hits by Rule Group"
          metrics = [
            ["AWS/WAFV2", "CountedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "aws-common-rules"],
            ["AWS/WAFV2", "CountedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "aws-sqli-rules"],
            ["AWS/WAFV2", "CountedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "aws-known-bad-inputs"],
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Bot Detections"
          metrics = [
            ["AWS/WAFV2", "CountedRequests", "WebACL", "shieldai-waf-${var.environment}", "Region", "us-east-1", "Rule", "aws-bot-control"],
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          view   = "timeSeries"
        }
      },
    ]
  })
}
