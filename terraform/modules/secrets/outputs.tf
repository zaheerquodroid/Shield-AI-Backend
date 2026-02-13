# -----------------------------------------------------------------------------
# ShieldAI Secrets Module — Outputs
# -----------------------------------------------------------------------------

output "secret_arn" {
  description = "ARN of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.proxy_secrets.arn
}

output "secret_name" {
  description = "Name of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.proxy_secrets.name
}

output "iam_policy_arn" {
  description = "ARN of the IAM policy granting secret read access"
  value       = aws_iam_policy.secrets_read.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for secret encryption"
  value       = aws_kms_key.secrets.arn
}
