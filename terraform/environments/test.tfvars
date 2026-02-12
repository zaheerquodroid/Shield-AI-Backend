# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Test Environment
# -----------------------------------------------------------------------------

environment   = "test"
cpu           = 256
memory        = 512
desired_count = 1
min_count     = 1
max_count     = 2

# WAF — count-only mode for testing
waf_block_mode     = false
enable_bot_control = false
header_preset      = "balanced"
