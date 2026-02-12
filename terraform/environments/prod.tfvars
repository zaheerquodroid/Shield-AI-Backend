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
