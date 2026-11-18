# ------------------------------------------------------------------------------
# Application Load Balancer: the only public entry point.
# Lives in the public subnets of both AZs and forwards to the instances'
# private IPs on port 8000. It only sends traffic to targets passing /health.
# ------------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [local.f.alb_security_group_id]
  subnets            = local.f.public_subnet_ids

  drop_invalid_header_fields = true   # reject malformed headers (request smuggling defence)
  enable_deletion_protection = false  # prod: true

  tags = { Name = "${var.project}-alb" }
}

resource "aws_lb_target_group" "app" {
  name                 = "${var.project}-tg"
  port                 = 8000
  protocol             = "HTTP"
  vpc_id               = local.f.vpc_id
  target_type          = "instance"
  deregistration_delay = 30   # let in-flight requests finish, but don't slow deploys for 5 min

  # Liveness only - /health does not touch the database, so a DB problem can't
  # make the ALB pull every instance out at once.
  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = "${var.project}-tg" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  # HTTPS would need a domain + ACM certificate; with one, this listener would
  # redirect to 443 instead.
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
