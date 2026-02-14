# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — DNS Record
#
# Creates a CNAME record pointing the customer domain to the security proxy
# (or directly to the app origin). Proxied through Cloudflare (orange cloud)
# to enable WAF, rate limiting, security headers, and DDoS protection.
# -----------------------------------------------------------------------------

resource "cloudflare_record" "proxy" {
  zone_id = var.zone_id
  name    = var.domain
  content = var.origin
  type    = "CNAME"
  proxied = var.dns_proxied
  ttl     = 1  # Automatic TTL when proxied

  comment = "ShieldAI edge security — ${var.environment}"
}
