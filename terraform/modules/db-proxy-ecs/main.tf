# -----------------------------------------------------------------------------
# ShieldAI DB Proxy — Stub ECS Fargate Task Definition
#
# NOTE: This is a stub module for future implementation. It provisions a
# minimal ECS cluster and task definition running postgres:15-alpine as a
# placeholder. Replace the container image and configuration with the actual
# DB proxy implementation when ready.
# -----------------------------------------------------------------------------

# ECS Cluster
resource "aws_ecs_cluster" "db_proxy" {
  name = "shieldai-db-proxy-${var.environment}"

  tags = {
    Name        = "shieldai-db-proxy-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Security Group — allow 5432 inbound only from the proxy security group
resource "aws_security_group" "db_proxy" {
  name        = "shieldai-db-proxy-${var.environment}"
  description = "Security group for ShieldAI DB proxy ECS tasks"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from proxy ECS tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.proxy_security_group_id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "shieldai-db-proxy-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Task Definition — stub using postgres:15-alpine
resource "aws_ecs_task_definition" "db_proxy" {
  family                   = "shieldai-db-proxy-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      # Stub container — replace with actual DB proxy image
      name      = "shieldai-db-proxy"
      image     = "postgres:15-alpine"
      essential = true

      portMappings = [
        {
          containerPort = 5432
          hostPort      = 5432
          protocol      = "tcp"
        }
      ]
    }
  ])

  tags = {
    Name        = "shieldai-db-proxy-task-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
