# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Root Module
# Composes the proxy-ecs and db-proxy-ecs modules
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------------------
# Proxy ECS Module — Security proxy with ALB, auto-scaling, and CloudWatch
# ---------------------------------------------------------------------------
module "proxy_ecs" {
  source = "./modules/proxy-ecs"

  vpc_id          = var.vpc_id
  subnet_ids      = var.subnet_ids
  environment     = var.environment
  proxy_image     = var.proxy_image
  cpu             = var.cpu
  memory          = var.memory
  desired_count   = var.desired_count
  min_count       = var.min_count
  max_count       = var.max_count
  certificate_arn = var.certificate_arn
  redis_url_ssm_arn    = var.redis_url_ssm_arn
  postgres_url_ssm_arn = var.postgres_url_ssm_arn
  api_key_ssm_arn      = var.api_key_ssm_arn

  # CloudFront origin protection (conditional)
  restrict_to_cloudfront    = var.enable_cloudfront
  origin_verify_secret      = var.cloudfront_origin_verify_secret
  cloudfront_prefix_list_id = var.enable_cloudfront ? module.cloudfront_saas[0].cloudfront_prefix_list_id : ""
}

# ---------------------------------------------------------------------------
# DB Proxy ECS Module — Stub for future database proxy implementation
# ---------------------------------------------------------------------------
module "db_proxy_ecs" {
  source = "./modules/db-proxy-ecs"

  vpc_id                  = var.vpc_id
  subnet_ids              = var.subnet_ids
  environment             = var.environment
  proxy_security_group_id = module.proxy_ecs.ecs_security_group_id
}

# ---------------------------------------------------------------------------
# WAF Module — AWS WAF WebACL with managed rulesets and rate limiting
# ---------------------------------------------------------------------------
module "waf" {
  source = "./modules/waf"

  environment        = var.environment
  waf_block_mode     = var.waf_block_mode
  alb_arn            = module.proxy_ecs.alb_arn
  auth_rate_limit    = var.auth_rate_limit
  global_rate_limit  = var.global_rate_limit
  enable_bot_control = var.enable_bot_control
  login_path_pattern = var.login_path_pattern
}

# ---------------------------------------------------------------------------
# Security Headers Module — CloudFront Response Headers Policy
# ---------------------------------------------------------------------------
module "security_headers" {
  source = "./modules/security-headers"

  environment        = var.environment
  header_preset      = var.header_preset
  csp_policy         = var.csp_policy
  permissions_policy = var.permissions_policy
}

# ---------------------------------------------------------------------------
# Secrets Module — AWS Secrets Manager with KMS encryption
# ---------------------------------------------------------------------------
module "secrets" {
  source = "./modules/secrets"

  environment         = var.environment
  rotation_days       = var.secrets_rotation_days
  rotation_lambda_arn = var.secrets_rotation_lambda_arn
  kms_deletion_window = var.secrets_kms_deletion_window
}

# ---------------------------------------------------------------------------
# CloudFront SaaS Module — Multi-tenant CDN distribution with edge WAF
# ---------------------------------------------------------------------------
# Fail-safe: CloudFront WAF (CLOUDFRONT scope) must be created in us-east-1.
# ACM certificates for CloudFront must also be in us-east-1.
check "cloudfront_region_check" {
  assert {
    condition     = !var.enable_cloudfront || var.region == "us-east-1"
    error_message = "CloudFront WAF and ACM certificates require us-east-1. Current region: ${var.region}. Either set region=us-east-1 or use a provider alias for the cloudfront_saas module."
  }
}

module "cloudfront_saas" {
  count  = var.enable_cloudfront ? 1 : 0
  source = "./modules/cloudfront-saas"

  environment                = var.environment
  alb_dns_name               = module.proxy_ecs.alb_dns_name
  response_headers_policy_id = module.security_headers.response_headers_policy_id
  origin_verify_secret       = var.cloudfront_origin_verify_secret
  cloudfront_certificate_arn = var.cloudfront_certificate_arn
  customer_domains           = var.customer_domains
  price_class                = var.cloudfront_price_class
  geo_restriction_type       = var.cloudfront_geo_restriction_type
  geo_restriction_locations  = var.cloudfront_geo_restriction_locations
  waf_block_mode             = var.waf_block_mode
  enable_bot_control         = var.enable_bot_control
  auth_rate_limit            = var.auth_rate_limit
  global_rate_limit          = var.global_rate_limit
  login_path_pattern         = var.login_path_pattern
  enable_logging             = var.cloudfront_enable_logging
  log_bucket_domain_name     = var.cloudfront_log_bucket
}

# Fail-safe: CloudFront and Cloudflare should not be enabled simultaneously.
# Both create DNS/CDN infrastructure that would conflict.
check "cloudfront_cloudflare_mutual_exclusion" {
  assert {
    condition     = !(var.enable_cloudfront && var.enable_cloudflare)
    error_message = "Cannot enable both CloudFront and Cloudflare simultaneously. Use one edge platform per deployment."
  }
}

# ---------------------------------------------------------------------------
# Cloudflare Edge Security Module — Alternative to AWS CloudFront
# Provides WAF, rate limiting, security headers, and zone security settings
# for non-AWS or Cloudflare-preferred deployments.
# ---------------------------------------------------------------------------
module "cloudflare_edge" {
  count  = var.enable_cloudflare ? 1 : 0
  source = "./modules/cloudflare-edge"

  zone_id     = var.cloudflare_zone_id
  environment = var.environment
  domain      = var.cloudflare_domain
  origin      = var.cloudflare_origin != "" ? var.cloudflare_origin : module.proxy_ecs.alb_dns_name

  # WAF
  waf_mode                 = var.waf_block_mode ? "block" : "log"
  enable_owasp_ruleset     = var.cloudflare_enable_owasp
  enable_credentials_check = var.cloudflare_enable_credentials_check

  # Rate limiting
  auth_rate_limit    = var.cloudflare_auth_rate_limit
  api_rate_limit     = var.cloudflare_api_rate_limit
  global_rate_limit  = var.cloudflare_global_rate_limit
  login_path_pattern = var.login_path_pattern

  # Security headers
  header_preset = var.header_preset
  csp_policy    = var.csp_policy

  # Zone settings
  ssl_mode              = var.cloudflare_ssl_mode
  min_tls_version       = var.cloudflare_min_tls_version
  always_use_https      = var.cloudflare_always_use_https
  enable_bot_fight_mode = var.cloudflare_enable_bot_fight_mode
  security_level        = var.cloudflare_security_level

  # DNS
  dns_proxied = var.cloudflare_dns_proxied
}
