# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Root Outputs
# -----------------------------------------------------------------------------

# --- Proxy ECS outputs ---

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.proxy_ecs.alb_dns_name
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = module.proxy_ecs.alb_arn
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = module.proxy_ecs.ecs_service_name
}

# --- WAF outputs ---

output "waf_web_acl_arn" {
  description = "ARN of the regional WAF WebACL (ALB)"
  value       = module.waf.web_acl_arn
}

# --- Security headers outputs ---

output "response_headers_policy_id" {
  description = "CloudFront response headers policy ID"
  value       = module.security_headers.response_headers_policy_id
}

# --- CloudFront outputs (conditional) ---

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = var.enable_cloudfront ? module.cloudfront_saas[0].distribution_id : ""
}

output "cloudfront_distribution_domain_name" {
  description = "CloudFront distribution domain name"
  value       = var.enable_cloudfront ? module.cloudfront_saas[0].distribution_domain_name : ""
}

output "cloudfront_waf_arn" {
  description = "CloudFront WAF WebACL ARN"
  value       = var.enable_cloudfront ? module.cloudfront_saas[0].waf_web_acl_arn : ""
}
