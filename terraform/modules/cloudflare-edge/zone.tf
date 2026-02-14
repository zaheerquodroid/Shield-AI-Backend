# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — Zone Settings
#
# Configures zone-level security settings:
# - SSL Full (Strict) — validates origin certificate
# - Minimum TLS 1.2 — disables legacy TLS versions
# - Always Use HTTPS — redirects HTTP to HTTPS
# - Security Level — Cloudflare threat score threshold
# - Bot Fight Mode — basic bot protection (free tier)
# -----------------------------------------------------------------------------

resource "cloudflare_zone_settings_override" "security" {
  zone_id = var.zone_id

  settings {
    ssl              = var.ssl_mode
    min_tls_version  = var.min_tls_version
    always_use_https = var.always_use_https ? "on" : "off"
    security_level   = var.security_level

    # Opportunistic encryption — upgrade HTTP/2 cleartext to encrypted
    opportunistic_encryption = "on"

    # Automatic HTTPS rewrites — fix mixed-content issues
    automatic_https_rewrites = "on"

    # TLS 1.3 — enable latest TLS version
    tls_1_3 = "on"
  }
}

# --- Bot Fight Mode ---
# Enabled via separate resource for clarity and conditional control
resource "cloudflare_bot_management" "bot_fight" {
  count   = var.enable_bot_fight_mode ? 1 : 0
  zone_id = var.zone_id

  fight_mode = true
}
