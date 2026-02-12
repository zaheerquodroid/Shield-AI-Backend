# -----------------------------------------------------------------------------
# ShieldAI DB Proxy — Module Outputs
# -----------------------------------------------------------------------------

output "security_group_id" {
  description = "Security group ID attached to the DB proxy ECS tasks"
  value       = aws_security_group.db_proxy.id
}
