# -----------------------------------------------------------------------------
# ShieldAI Security Proxy — Application Load Balancer
# -----------------------------------------------------------------------------

# ALB Security Group — allow inbound 80 and 443 (optionally restricted to CloudFront)
resource "aws_security_group" "alb" {
  name        = "shieldai-proxy-alb-${var.environment}"
  description = "Security group for the ShieldAI proxy ALB"
  vpc_id      = var.vpc_id

  # When restrict_to_cloudfront is false, allow HTTPS from anywhere (backwards compatible)
  dynamic "ingress" {
    for_each = var.restrict_to_cloudfront ? [] : [1]
    content {
      description = "HTTPS from anywhere"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  # When restrict_to_cloudfront is true, allow HTTPS only from CloudFront prefix list
  dynamic "ingress" {
    for_each = var.restrict_to_cloudfront ? [1] : []
    content {
      description     = "HTTPS from CloudFront only"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = [var.cloudfront_prefix_list_id]
    }
  }

  dynamic "ingress" {
    for_each = var.restrict_to_cloudfront ? [] : [1]
    content {
      description = "HTTP from anywhere (redirected to HTTPS)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = var.restrict_to_cloudfront ? [1] : []
    content {
      description     = "HTTP from CloudFront only (redirected to HTTPS)"
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      prefix_list_ids = [var.cloudfront_prefix_list_id]
    }
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
  load_balancer_type         = "application"
  enable_deletion_protection = var.environment == "prod"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.subnet_ids

  access_logs {
    bucket  = var.alb_access_logs_bucket
    prefix  = "shieldai-proxy-${var.environment}"
    enabled = var.enable_alb_access_logs
  }

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

# --- Origin Verify Header Check (defense-in-depth) ---
# When CloudFront restriction is enabled, verify the X-ShieldAI-Origin-Verify
# secret header. The ALB default action forwards all traffic, so we add a
# higher-priority rule that FORWARDS only when the header matches, and a
# lower-priority catch-all that BLOCKS everything else.
#
# Rule 1 (priority 1): Header matches → forward to target group (allow)
# Rule 2 (priority 100): Catch-all → 403 (deny all other traffic)
resource "aws_lb_listener_rule" "allow_verified_origin" {
  count        = var.restrict_to_cloudfront && var.origin_verify_secret != "" ? 1 : 0
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }

  condition {
    http_header {
      http_header_name = "X-ShieldAI-Origin-Verify"
      values           = [var.origin_verify_secret]
    }
  }
}

resource "aws_lb_listener_rule" "deny_unverified_origin" {
  count        = var.restrict_to_cloudfront && var.origin_verify_secret != "" ? 1 : 0
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }

  # Match all paths — catch-all rule
  condition {
    path_pattern {
      values = ["/*"]
    }
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
