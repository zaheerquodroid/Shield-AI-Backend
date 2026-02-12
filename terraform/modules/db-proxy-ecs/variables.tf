# -----------------------------------------------------------------------------
# ShieldAI DB Proxy — ECS Module Variables
# -----------------------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID where the DB proxy infrastructure will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the DB proxy ECS service"
  type        = list(string)
}

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "proxy_security_group_id" {
  description = "Security group ID of the ShieldAI proxy ECS tasks (allowed to connect to DB proxy)"
  type        = string
}
