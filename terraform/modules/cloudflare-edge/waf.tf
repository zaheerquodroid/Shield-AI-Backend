# -----------------------------------------------------------------------------
# ShieldAI — Cloudflare Edge Security Module — WAF Managed Rulesets
#
# Deploys Cloudflare managed WAF rulesets:
# 1. Cloudflare Managed Ruleset (SQLi, XSS, RCE, LFI, etc.)
# 2. OWASP Core Ruleset (OWASP ModSecurity CRS equivalent)
# 3. Exposed Credentials Check (credential stuffing detection)
#
# Mode: "block" for production, "log" for test environments.
# In "log" mode, rules use action_parameters.overrides to set action to "log".
# -----------------------------------------------------------------------------

locals {
  waf_action = var.waf_mode == "block" ? "block" : "log"

  # Cloudflare managed ruleset IDs (stable across all zones)
  cf_managed_ruleset_id    = "efb7b8c949ac4650a09736fc376e9aee"
  owasp_core_ruleset_id    = "4814384a9e5d4991b9815dcfc25d2f1f"
  credentials_check_id     = "c2e184081120413c86c3ab7e14069605"
}

resource "cloudflare_ruleset" "waf" {
  zone_id     = var.zone_id
  name        = "ShieldAI WAF — ${var.environment}"
  description = "Managed WAF rulesets for ShieldAI edge security"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  # --- Cloudflare Managed Ruleset (SQLi, XSS, RCE, etc.) ---
  rules {
    action      = "execute"
    expression  = "true"
    description = "Deploy Cloudflare Managed Ruleset"
    enabled     = true

    action_parameters {
      id = local.cf_managed_ruleset_id

      overrides {
        action = local.waf_action
      }
    }
  }

  # --- OWASP Core Ruleset ---
  dynamic "rules" {
    for_each = var.enable_owasp_ruleset ? [1] : []

    content {
      action      = "execute"
      expression  = "true"
      description = "Deploy OWASP Core Ruleset"
      enabled     = true

      action_parameters {
        id = local.owasp_core_ruleset_id

        overrides {
          action = local.waf_action
        }
      }
    }
  }

  # --- Exposed Credentials Check ---
  dynamic "rules" {
    for_each = var.enable_credentials_check ? [1] : []

    content {
      action      = "execute"
      expression  = "true"
      description = "Deploy Exposed Credentials Check"
      enabled     = true

      action_parameters {
        id = local.credentials_check_id

        overrides {
          action = local.waf_action
        }
      }
    }
  }
}
