output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.id
}

output "app_package_key" {
  value = aws_s3_object.app.key
}

output "asg_name" {
  value = aws_autoscaling_group.app.name
}

output "nat_public_ip" {
  description = "The address all outbound traffic from the instances comes from."
  value       = aws_eip.nat.public_ip
}

output "app_url" {
  description = "Open this in a browser."
  value       = "http://${aws_lb.app.dns_name}"
}

output "target_group_arn" {
  value = aws_lb_target_group.app.arn
}
