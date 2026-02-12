# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Application Load Balancer
# -----------------------------------------------------------------------------

# ALB Security Group — allow inbound 80 and 443 from anywhere
resource "aws_security_group" "alb" {
  name        = "shieldai-proxy-alb-${var.environment}"
  description = "Security group for the ShieldAI proxy ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere (redirected to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "shieldai-proxy-alb-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ECS Tasks Security Group — allow 8080 inbound only from ALB SG
resource "aws_security_group" "ecs_tasks" {
  name        = "shieldai-proxy-ecs-${var.environment}"
  description = "Security group for ShieldAI proxy ECS tasks"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow traffic from ALB on port 8080"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "shieldai-proxy-ecs-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Application Load Balancer (public-facing)
resource "aws_lb" "proxy" {
  name               = "shieldai-proxy-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  tags = {
    Name        = "shieldai-proxy-alb-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Target Group — port 8080 with /health check
resource "aws_lb_target_group" "proxy" {
  name        = "shieldai-proxy-${var.environment}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  tags = {
    Name        = "shieldai-proxy-tg-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# HTTPS Listener (443) — forward to target group using ACM certificate
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.proxy.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }

  tags = {
    Name        = "shieldai-proxy-https-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# HTTP Listener (80) — redirect to HTTPS
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.proxy.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = {
    Name        = "shieldai-proxy-http-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
