# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Module Outputs
# -----------------------------------------------------------------------------

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.proxy.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID of the Application Load Balancer (for Route53 alias records)"
  value       = aws_lb.proxy.zone_id
}

output "target_group_arn" {
  description = "ARN of the ALB target group"
  value       = aws_lb_target_group.proxy.arn
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.proxy.name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.proxy.name
}

output "ecs_security_group_id" {
  description = "Security group ID attached to the ECS tasks"
  value       = aws_security_group.ecs_tasks.id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.proxy.arn
}

output "alb_security_group_id" {
  description = "Security group ID attached to the ALB"
  value       = aws_security_group.alb.id
}
