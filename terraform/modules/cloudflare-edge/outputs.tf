# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — Outputs
# -----------------------------------------------------------------------------

output "waf_ruleset_id" {
  description = "ID of the Cloudflare WAF managed ruleset"
  value       = cloudflare_ruleset.waf.id
}

output "rate_limiting_ruleset_id" {
  description = "ID of the Cloudflare rate limiting ruleset"
  value       = cloudflare_ruleset.rate_limiting.id
}

output "security_headers_ruleset_id" {
  description = "ID of the Cloudflare security headers ruleset"
  value       = cloudflare_ruleset.security_headers.id
}

output "dns_record_id" {
  description = "ID of the Cloudflare DNS record"
  value       = cloudflare_record.proxy.id
}

output "dns_record_hostname" {
  description = "Hostname of the DNS record"
  value       = cloudflare_record.proxy.hostname
}

output "zone_settings_id" {
  description = "ID of the zone settings override"
  value       = cloudflare_zone_settings_override.security.id
}
