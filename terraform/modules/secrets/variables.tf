# -----------------------------------------------------------------------------
# ShieldAI Secrets Module — Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "rotation_days" {
  description = "Automatic rotation period in days (0 = disabled)"
  type        = number
  default     = 0
}

variable "rotation_lambda_arn" {
  description = "ARN of the Lambda function for secret rotation (required if rotation_days > 0)"
  type        = string
  default     = ""
}

variable "kms_deletion_window" {
  description = "KMS key deletion window in days (7-30)"
  type        = number
  default     = 14

  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}
