# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — ECS Fargate Task Definition + Service
# -----------------------------------------------------------------------------

# ECS Cluster
resource "aws_ecs_cluster" "proxy" {
  name = "shieldai-proxy-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "shieldai-proxy-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# IAM Role — ECS Task Execution
resource "aws_iam_role" "ecs_task_execution" {
  name = "shieldai-proxy-exec-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "shieldai-proxy-exec-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_ssm_access" {
  name = "shieldai-proxy-ssm-${var.environment}"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = [
          var.redis_url_ssm_arn,
          var.postgres_url_ssm_arn,
          var.api_key_ssm_arn,
        ]
      }
    ]
  })
}

# IAM Role — ECS Task (runtime permissions for the container)
resource "aws_iam_role" "ecs_task" {
  name = "shieldai-proxy-task-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "shieldai-proxy-task-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "proxy" {
  name              = "${var.log_group_name}-${var.environment}"
  retention_in_days = 30

  tags = {
    Name        = "shieldai-proxy-logs-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "proxy" {
  family                   = "shieldai-proxy-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "shieldai-proxy"
      image     = var.proxy_image
      essential = true

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "PROXY_LOG_JSON"
          value = "true"
        }
      ]

      secrets = [
        {
          name      = "PROXY_REDIS_URL"
          valueFrom = var.redis_url_ssm_arn
        },
        {
          name      = "PROXY_POSTGRES_URL"
          valueFrom = var.postgres_url_ssm_arn
        },
        {
          name      = "PROXY_API_KEY"
          valueFrom = var.api_key_ssm_arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.proxy.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "proxy"
        }
      }
    }
  ])

  tags = {
    Name        = "shieldai-proxy-task-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Current AWS region data source
data "aws_region" "current" {}

# ECS Service
resource "aws_ecs_service" "proxy" {
  name            = "shieldai-proxy-${var.environment}"
  cluster         = aws_ecs_cluster.proxy.id
  task_definition = aws_ecs_task_definition.proxy.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "shieldai-proxy"
    container_port   = 8080
  }

  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy_attachment.ecs_task_execution,
  ]

  tags = {
    Name        = "shieldai-proxy-svc-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
