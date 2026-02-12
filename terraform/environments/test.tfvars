# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Test Environment
# -----------------------------------------------------------------------------

environment   = "test"
cpu           = 256
memory        = 512
desired_count = 1
min_count     = 1
max_count     = 2

# SSM Parameter Store ARNs for secrets
redis_url_ssm_arn    = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/test/redis-url"
postgres_url_ssm_arn = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/test/postgres-url"
api_key_ssm_arn      = "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/shieldai/test/api-key"

# WAF — count-only mode for testing
waf_block_mode     = false
enable_bot_control = false
header_preset      = "balanced"
