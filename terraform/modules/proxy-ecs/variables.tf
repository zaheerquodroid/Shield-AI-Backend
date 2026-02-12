# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — ECS Module Variables
# -----------------------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID where the proxy infrastructure will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the ECS service and ALB"
  type        = list(string)
}

variable "environment" {
  description = "Deployment environment (test, demo, prod)"
  type        = string
}

variable "proxy_image" {
  description = "Docker image URI for the ShieldAI security proxy"
  type        = string
}

variable "cpu" {
  description = "CPU units for the Fargate task (1 vCPU = 1024)"
  type        = number
  default     = 256
}

variable "memory" {
  description = "Memory in MiB for the Fargate task"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 1
}

variable "min_count" {
  description = "Minimum number of ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

variable "max_count" {
  description = "Maximum number of ECS tasks for auto-scaling"
  type        = number
  default     = 10
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS on the ALB"
  type        = string
}

variable "redis_url" {
  description = "Connection URL for the Redis instance used by the proxy"
  type        = string
  sensitive   = true
}

variable "postgres_url" {
  description = "Connection URL for the PostgreSQL database used by the proxy"
  type        = string
  sensitive   = true
}

variable "api_key" {
  description = "API key for the ShieldAI proxy service"
  type        = string
  sensitive   = true
}

variable "log_group_name" {
  description = "CloudWatch log group name for proxy container logs"
  type        = string
  default     = "/ecs/shieldai-proxy"
}
