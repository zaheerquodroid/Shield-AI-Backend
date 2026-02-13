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
