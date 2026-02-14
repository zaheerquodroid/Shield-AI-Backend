# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Demo Environment
# -----------------------------------------------------------------------------

environment   = "demo"
cpu           = 256
memory        = 512
desired_count = 1
min_count     = 1
max_count     = 4

# SSM Parameter Store ARNs for secrets
redis_url_ssm_arn    = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/demo/redis-url"
postgres_url_ssm_arn = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/demo/postgres-url"
api_key_ssm_arn      = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/demo/api-key"

# WAF — count-only mode for demo
waf_block_mode     = false
enable_bot_control = false
header_preset      = "balanced"

# CloudFront — disabled by default for demo (opt-in)
enable_cloudfront = false

# Cloudflare — disabled by default for demo (opt-in)
enable_cloudflare = false
