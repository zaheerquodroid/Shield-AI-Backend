# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Production Environment
# -----------------------------------------------------------------------------

environment   = "prod"
cpu           = 512
memory        = 1024
desired_count = 2
min_count     = 2
max_count     = 10

# WAF — block mode in production
waf_block_mode     = true
enable_bot_control = false
header_preset      = "strict"
