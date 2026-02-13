# -----------------------------------------------------------------------------
# ShieldAI — Secrets Management Module
# AWS Secrets Manager secret with KMS CMK encryption and IAM policy
# -----------------------------------------------------------------------------

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ---------------------------------------------------------------------------
# KMS Customer Managed Key for secret encryption
# ---------------------------------------------------------------------------

resource "aws_kms_key" "secrets" {
  description             = "ShieldAI secrets encryption key (${var.environment})"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true

  tags = {
    Name        = "shieldai-secrets-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/shieldai-secrets-${var.environment}"
  target_key_id = aws_kms_key.secrets.key_id
}

# ---------------------------------------------------------------------------
# Secrets Manager secret
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "proxy_secrets" {
  name        = "shieldai/proxy/${var.environment}"
  description = "ShieldAI proxy secrets (${var.environment})"
  kms_key_id  = aws_kms_key.secrets.arn

  tags = {
    Name        = "shieldai-proxy-secrets-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_secretsmanager_secret_version" "proxy_secrets" {
  secret_id = aws_secretsmanager_secret.proxy_secrets.id

  # Initial placeholder — real values injected out-of-band or via CI/CD
  secret_string = jsonencode({
    redis_url    = "redis://localhost:6379"
    postgres_url = "postgresql://shieldai:shieldai@localhost:5432/shieldai"
    api_key      = "CHANGE_ME"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---------------------------------------------------------------------------
# Secret rotation schedule
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret_rotation" "proxy_secrets" {
  count = var.rotation_days > 0 ? 1 : 0

  secret_id           = aws_secretsmanager_secret.proxy_secrets.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# ---------------------------------------------------------------------------
# IAM policy granting read access to the secret
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "secrets_read" {
  statement {
    sid    = "AllowGetSecretValue"
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]

    resources = [aws_secretsmanager_secret.proxy_secrets.arn]
  }

  statement {
    sid    = "AllowKMSDecrypt"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.secrets.arn]
  }
}

resource "aws_iam_policy" "secrets_read" {
  name        = "shieldai-secrets-read-${var.environment}"
  description = "Allow reading ShieldAI proxy secrets"
  policy      = data.aws_iam_policy_document.secrets_read.json

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
