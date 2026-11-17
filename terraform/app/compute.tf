# ------------------------------------------------------------------------------
# Instances: a launch template ("the recipe") + an Auto Scaling Group that keeps
# the desired number of instances running across both AZs and replaces broken ones.
# ------------------------------------------------------------------------------

# Latest Amazon Linux 2023 AMI, published by AWS in SSM Parameter Store.
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_launch_template" "app" {
  name_prefix   = "${var.project}-app-"
  image_id      = data.aws_ssm_parameter.al2023.value
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }

  vpc_security_group_ids = [local.f.app_security_group_id]

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    region        = var.region
    bucket        = aws_s3_bucket.artifacts.id
    object_key    = aws_s3_object.app.key
    db_secret_arn = local.f.db_master_secret_arn
    db_host       = local.f.db_address
    db_port       = local.f.db_port
    db_name       = local.f.db_name
  }))

  # IMDSv2 only: blocks SSRF-style theft of the instance role credentials.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 8
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  # default_tags don't reach instances launched by an ASG - tag them explicitly
  # so they show up under Project=phishing-detector in Cost Explorer.
  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.project}-app", Project = var.project, Stack = "app" }
  }

  tag_specifications {
    resource_type = "volume"
    tags          = { Name = "${var.project}-app", Project = var.project, Stack = "app" }
  }

  update_default_version = true
}

resource "aws_autoscaling_group" "app" {
  name                = "${var.project}-asg"
  vpc_zone_identifier = local.f.private_app_subnet_ids   # spread across both AZs

  min_size         = var.asg_min
  desired_capacity = var.asg_desired
  max_size         = var.asg_max

  health_check_type         = "EC2"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  # New launch template version (new code, new user data) -> replace instances gradually.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-app"
    propagate_at_launch = true
  }

  # The NAT route must exist before instances boot, or user data can't install anything.
  depends_on = [aws_route.private_app_to_nat]
}
