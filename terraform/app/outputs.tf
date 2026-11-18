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

output "dashboard_url" {
  description = "CloudWatch dashboard: health, CPU/memory, requests, success/failure, logs."
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "app_log_group" {
  description = "Where the application logs are."
  value       = aws_cloudwatch_log_group.app.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "cache_endpoint" {
  description = "ElastiCache (Valkey) primary endpoint - reachable only from the app instances."
  value       = aws_elasticache_replication_group.cache.primary_endpoint_address
}
