# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Demo Environment
# -----------------------------------------------------------------------------

environment   = "demo"
cpu           = 256
memory        = 512
desired_count = 1
min_count     = 1
max_count     = 4

# WAF — count-only mode for demo
waf_block_mode     = false
enable_bot_control = false
header_preset      = "balanced"
