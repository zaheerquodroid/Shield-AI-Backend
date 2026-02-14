# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Production Environment
# -----------------------------------------------------------------------------

environment   = "prod"
cpu           = 512
memory        = 1024
desired_count = 2
min_count     = 2
max_count     = 10

# SSM Parameter Store ARNs for secrets
redis_url_ssm_arn    = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/prod/redis-url"
postgres_url_ssm_arn = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/prod/postgres-url"
api_key_ssm_arn      = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/prod/api-key"

# WAF — block mode in production
waf_block_mode     = true
enable_bot_control = false
header_preset      = "strict"

# CloudFront — enabled in production
enable_cloudfront          = true
cloudfront_price_class     = "PriceClass_100"
cloudfront_certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERTIFICATE_ID"
cloudfront_enable_logging  = true
cloudfront_log_bucket      = "shieldai-cloudfront-logs-prod.s3.amazonaws.com"
# IMPORTANT: cloudfront_origin_verify_secret must be provided via:
#   TF_VAR_cloudfront_origin_verify_secret or -var flag (>= 32 chars)
# Do NOT hardcode secrets in tfvars files.

# Cloudflare — disabled (use CloudFront for AWS-native deployments)
enable_cloudflare = false
