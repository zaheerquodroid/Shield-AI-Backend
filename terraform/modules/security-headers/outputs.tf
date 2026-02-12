# -----------------------------------------------------------------------------
# ShieldAI — Security Headers Module Outputs
# -----------------------------------------------------------------------------

output "response_headers_policy_id" {
  description = "ID of the CloudFront response headers policy"
  value       = aws_cloudfront_response_headers_policy.security.id
}
