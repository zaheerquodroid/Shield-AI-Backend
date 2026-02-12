# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Headers Module Outputs
# -----------------------------------------------------------------------------

output "ruleset_id" {
  description = "ID of the Cloudflare transform ruleset"
  value       = cloudflare_ruleset.security_headers.id
}
