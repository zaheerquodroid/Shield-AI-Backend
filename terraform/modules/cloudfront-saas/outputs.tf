# -----------------------------------------------------------------------------
# ShieldAI — CloudFront SaaS Distribution Module Outputs
# -----------------------------------------------------------------------------

output "distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.proxy.id
}

output "distribution_domain_name" {
  description = "CloudFront distribution domain name (d123.cloudfront.net)"
  value       = aws_cloudfront_distribution.proxy.domain_name
}

output "distribution_arn" {
  description = "CloudFront distribution ARN"
  value       = aws_cloudfront_distribution.proxy.arn
}

output "distribution_hosted_zone_id" {
  description = "Route53 hosted zone ID for CloudFront alias records (Z2FDTNDATAQYW2)"
  value       = aws_cloudfront_distribution.proxy.hosted_zone_id
}

output "waf_web_acl_arn" {
  description = "CloudFront WAF WebACL ARN"
  value       = aws_wafv2_web_acl.cloudfront.arn
}

output "cloudfront_prefix_list_id" {
  description = "AWS managed prefix list ID for CloudFront IP ranges (for ALB SG)"
  value       = data.aws_ec2_managed_prefix_list.cloudfront.id
}
