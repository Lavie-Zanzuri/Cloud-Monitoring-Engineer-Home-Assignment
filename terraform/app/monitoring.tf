# ------------------------------------------------------------------------------
# Monitoring: answers the four questions in the assignment.
#
#   1. Are the EC2 instances healthy?      -> ALB Healthy/UnHealthyHostCount, ASG InService
#   2. CPU / system usage?                 -> EC2 CPU + memory/disk from the CloudWatch agent
#   3. How many requests hit the ALB?      -> ALB RequestCount
#   4. Success vs failure?                 -> HTTP 2XX / 4XX / 5XX (target + ALB) and success rate %
#   +  Where are the app logs?             -> CloudWatch Logs group /phishing-detector/app
#
# Everything lands on one dashboard; the important conditions also raise alarms
# that email you through SNS.
# Cost: logs are kept 7 days; 10 alarms / ~10 custom metrics stay at or near the
# CloudWatch free tier.
# ------------------------------------------------------------------------------

locals {
  lb_dim  = aws_lb.app.arn_suffix               # "app/phishing-detector-alb/abc123"
  tg_dim  = aws_lb_target_group.app.arn_suffix  # "targetgroup/phishing-detector-tg/def456"
  asg     = aws_autoscaling_group.app.name
  db_id   = local.f.db_instance_id
  cache_node = tolist(aws_elasticache_replication_group.cache.member_clusters)[0]   # "...-cache-001"
  metrics = "PhishingDetector"                  # namespace for metrics derived from app logs

  app_log_group       = "/${var.project}/app"
  user_data_log_group = "/${var.project}/user-data"
}

# ---------- Logs ----------
# Created here (not by the agent) so retention is set and `destroy` removes them.

resource "aws_cloudwatch_log_group" "app" {
  name              = local.app_log_group
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "user_data" {
  name              = local.user_data_log_group
  retention_in_days = 7
}

# Logs -> metrics. The app writes one JSON object per line, so filters can match fields.

# Scans per verdict (Safe / Suspicious / Phishing) - a business metric.
resource "aws_cloudwatch_log_metric_filter" "scans" {
  name           = "scans-by-verdict"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "{ $.message = \"scan\" }"

  metric_transformation {
    name       = "Scans"
    namespace  = local.metrics
    value      = "1"
    unit       = "Count"
    dimensions = { Verdict = "$.verdict" }
  }
}

# Any ERROR line the app logs (e.g. DB unreachable, scan could not be saved).
resource "aws_cloudwatch_log_metric_filter" "errors" {
  name           = "app-errors"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "{ $.level = \"ERROR\" }"

  metric_transformation {
    name          = "AppErrors"
    namespace     = local.metrics
    value         = "1"
    default_value = 0
    unit          = "Count"
  }
}

# ---------- Notifications ----------

# Not encrypted with the AWS-managed SNS key on purpose: CloudWatch alarms can't
# publish to it (would need a customer-managed KMS key with a key policy).
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

# Only created if an email was given. AWS sends a confirmation link - click it,
# otherwise nothing is delivered.
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------- Alarms ----------
# ok_actions too, so you also get the "recovered" email.

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.project}-unhealthy-hosts"
  alarm_description   = "At least one instance is failing the ALB /health check."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = { LoadBalancer = local.lb_dim, TargetGroup = local.tg_dim }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "healthy_below_min" {
  alarm_name          = "${var.project}-healthy-hosts-below-min"
  alarm_description   = "Fewer healthy instances than the ASG minimum - capacity/redundancy is reduced."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = { LoadBalancer = local.lb_dim, TargetGroup = local.tg_dim }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = var.asg_min
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${var.project}-app-5xx"
  alarm_description   = "The app itself is returning 5xx errors."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = local.lb_dim }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"   # no requests = no errors
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "elb_5xx" {
  alarm_name          = "${var.project}-alb-5xx"
  alarm_description   = "The load balancer itself returns 502/503/504 - usually no healthy target or a target timing out."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  dimensions          = { LoadBalancer = local.lb_dim }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "latency_p95" {
  alarm_name          = "${var.project}-latency-p95"
  alarm_description   = "95% of requests should finish within 1 second."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  dimensions          = { LoadBalancer = local.lb_dim }
  extended_statistic  = "p95"            # percentile, not average: averages hide the slow tail
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# Scaling starts at 50%. Sustained 80% means scaling isn't keeping up (or hit asg_max).
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.project}-cpu-high"
  alarm_description   = "Average CPU across the ASG above 80% for 5 minutes."
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { AutoScalingGroupName = local.asg }
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 5
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# EC2 doesn't report memory on its own - this comes from the CloudWatch agent.
resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "${var.project}-memory-high"
  alarm_description   = "Average memory use across the ASG above 85% (t3.micro has 1 GB)."
  namespace           = "CWAgent"
  metric_name         = "mem_used_percent"
  dimensions          = { AutoScalingGroupName = local.asg }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 85
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "app_errors" {
  alarm_name          = "${var.project}-app-errors"
  alarm_description   = "The app logged ERROR lines - check the app log group."
  namespace           = local.metrics
  metric_name         = "AppErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.project}-rds-cpu-high"
  alarm_description   = "Database CPU above 80% for 15 minutes."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = local.db_id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.project}-rds-storage-low"
  alarm_description   = "Less than 2 GB free on the 20 GB database volume."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = local.db_id }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 2 * 1024 * 1024 * 1024   # bytes
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

locals {
  all_alarm_arns = [
    aws_cloudwatch_metric_alarm.unhealthy_hosts.arn,
    aws_cloudwatch_metric_alarm.healthy_below_min.arn,
    aws_cloudwatch_metric_alarm.target_5xx.arn,
    aws_cloudwatch_metric_alarm.elb_5xx.arn,
    aws_cloudwatch_metric_alarm.latency_p95.arn,
    aws_cloudwatch_metric_alarm.cpu_high.arn,
    aws_cloudwatch_metric_alarm.memory_high.arn,
    aws_cloudwatch_metric_alarm.app_errors.arn,
    aws_cloudwatch_metric_alarm.rds_cpu.arn,
    aws_cloudwatch_metric_alarm.rds_storage.arn,
  ]
}

# ---------- Dashboard ----------
# 24-column grid. Row by row: answers first, then details, then logs.

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.project

  dashboard_body = jsonencode({
    widgets = [
      # --- Row 0: how to read this dashboard + where the logs are
      {
        type = "text", x = 0, y = 0, width = 24, height = 3
        properties = {
          markdown = join("\n", [
            "## Phishing Detector - ${var.region}",
            "**App logs:** CloudWatch Logs `${local.app_log_group}` (one stream per instance, JSON lines) - on the instance: `/var/log/phishing/app.log`.  ",
            "**Boot logs:** `${local.user_data_log_group}` - on the instance: `/var/log/user-data.log`.  ",
            "Shell access: Systems Manager > Session Manager (no SSH). Alarms are emailed via SNS topic `${aws_sns_topic.alerts.name}`.",
          ])
        }
      },

      # --- Row 1: health
      {
        type = "metric", x = 0, y = 3, width = 8, height = 6
        properties = {
          title  = "1. Instance health (ALB target checks)"
          region = var.region
          stat   = "Minimum"
          period = 60
          view   = "timeSeries"
          metrics = [
            ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", local.tg_dim, "LoadBalancer", local.lb_dim, { color = "#2ca02c" }],
            ["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", local.tg_dim, "LoadBalancer", local.lb_dim, { color = "#d62728", stat = "Maximum" }],
          ]
          yAxis = { left = { min = 0 } }
        }
      },
      {
        type = "metric", x = 8, y = 3, width = 8, height = 6
        properties = {
          title  = "Auto Scaling group: in service vs desired"
          region = var.region
          stat   = "Average"
          period = 60
          metrics = [
            ["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg],
            ["AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", local.asg],
            ["AWS/AutoScaling", "GroupPendingInstances", "AutoScalingGroupName", local.asg],
          ]
          yAxis = { left = { min = 0 } }
        }
      },
      {
        type = "alarm", x = 16, y = 3, width = 8, height = 6
        properties = {
          title  = "Alarms"
          alarms = local.all_alarm_arns
        }
      },

      # --- Row 2: traffic and success/failure
      {
        type = "metric", x = 0, y = 9, width = 8, height = 6
        properties = {
          title  = "3. Requests through the load balancer"
          region = var.region
          stat   = "Sum"
          period = 60
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.lb_dim],
          ]
          yAxis = { left = { min = 0 } }
        }
      },
      {
        type = "metric", x = 8, y = 9, width = 8, height = 6
        properties = {
          title  = "4. Responses by status code"
          region = var.region
          stat   = "Sum"
          period = 60
          view   = "timeSeries"
          stacked = true
          metrics = [
            ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.lb_dim, { label = "2xx (app)", color = "#2ca02c" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.lb_dim, { label = "4xx (app)", color = "#ff7f0e" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.lb_dim, { label = "5xx (app)", color = "#d62728" }],
            ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.lb_dim, { label = "5xx (ALB)", color = "#9467bd" }],
          ]
        }
      },
      {
        type = "metric", x = 16, y = 9, width = 8, height = 6
        properties = {
          title  = "4. Success rate % and p95 latency"
          region = var.region
          period = 60
          metrics = [
            [{ expression = "100 * FILL(m1, 0) / m2", label = "Success rate % (2xx / all)", id = "e1" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.lb_dim, { id = "m1", stat = "Sum", visible = false }],
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.lb_dim, { id = "m2", stat = "Sum", visible = false }],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb_dim, { stat = "p95", label = "p95 latency (s)", yAxis = "right" }],
          ]
          yAxis = { left = { min = 0, max = 100 }, right = { min = 0 } }
        }
      },

      # --- Row 3: system usage
      {
        type = "metric", x = 0, y = 15, width = 8, height = 6
        properties = {
          title  = "2. CPU % per instance"
          region = var.region
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', 60)", id = "e1" }],
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", local.asg, { label = "ASG average", stat = "Average" }],
          ]
          annotations = { horizontal = [{ value = 50, label = "scale-out target" }] }
          yAxis       = { left = { min = 0, max = 100 } }
        }
      },
      {
        type = "metric", x = 8, y = 15, width = 8, height = 6
        properties = {
          title  = "2. Memory % per instance (CloudWatch agent)"
          region = var.region
          period = 60
          metrics = [
            [{ expression = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId} MetricName=\"mem_used_percent\" AutoScalingGroupName=\"${local.asg}\"', 'Average', 60)", id = "e1" }],
          ]
          yAxis = { left = { min = 0, max = 100 } }
        }
      },
      {
        type = "metric", x = 16, y = 15, width = 8, height = 6
        properties = {
          title  = "2. Root disk % used (ASG average)"
          region = var.region
          stat   = "Average"
          period = 300
          metrics = [
            ["CWAgent", "disk_used_percent", "AutoScalingGroupName", local.asg],
          ]
          yAxis = { left = { min = 0, max = 100 } }
        }
      },

      # --- Row 4: application and database
      {
        type = "metric", x = 0, y = 21, width = 8, height = 6
        properties = {
          title   = "Scans by verdict (from app logs)"
          region  = var.region
          stat    = "Sum"
          period  = 300
          stacked = true
          metrics = [
            [local.metrics, "Scans", "Verdict", "Safe", { color = "#2ca02c" }],
            [local.metrics, "Scans", "Verdict", "Suspicious", { color = "#ff7f0e" }],
            [local.metrics, "Scans", "Verdict", "Phishing", { color = "#d62728" }],
          ]
        }
      },
      {
        type = "metric", x = 8, y = 21, width = 8, height = 6
        properties = {
          title  = "App ERROR log lines"
          region = var.region
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics, "AppErrors", { color = "#d62728" }],
          ]
          yAxis = { left = { min = 0 } }
        }
      },
      {
        type = "metric", x = 16, y = 21, width = 8, height = 6
        properties = {
          title  = "Database (RDS)"
          region = var.region
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", local.db_id, { label = "CPU %" }],
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", local.db_id, { label = "Connections", yAxis = "right" }],
          ]
          yAxis = { left = { min = 0, max = 100 }, right = { min = 0 } }
        }
      },

      # --- Row 5: logs (Logs Insights queries over the JSON request log)
      {
        type = "log", x = 0, y = 27, width = 16, height = 7
        properties = {
          title  = "Latest requests"
          region = var.region
          view   = "table"
          query  = "SOURCE '${local.app_log_group}' | fields @timestamp, instance, method, path, status, latency_ms | filter message = 'request' | sort @timestamp desc | limit 50"
        }
      },
      {
        type = "log", x = 16, y = 27, width = 8, height = 7
        properties = {
          title  = "Requests per instance (load balancing)"
          region = var.region
          view   = "table"
          query  = "SOURCE '${local.app_log_group}' | filter message = 'request' | stats count(*) as requests, avg(latency_ms) as avg_ms by instance"
        }
      },
      {
        type = "log", x = 0, y = 34, width = 24, height = 6
        properties = {
          title  = "Errors and failed requests"
          region = var.region
          view   = "table"
          query  = "SOURCE '${local.app_log_group}' | fields @timestamp, instance, level, message, path, status, error | filter level = 'ERROR' or status >= 500 | sort @timestamp desc | limit 50"
        }
      },

      # --- Row 7: cache (ElastiCache / Valkey)
      {
        type = "metric", x = 0, y = 40, width = 12, height = 6
        properties = {
          title  = "Cache: hits vs misses, hit rate %"
          region = var.region
          period = 60
          metrics = [
            ["AWS/ElastiCache", "CacheHits", "CacheClusterId", local.cache_node, { id = "h", stat = "Sum", color = "#2ca02c" }],
            ["AWS/ElastiCache", "CacheMisses", "CacheClusterId", local.cache_node, { id = "m", stat = "Sum", color = "#ff7f0e" }],
            [{ expression = "100 * h / (h + m)", label = "Hit rate %", id = "e1", yAxis = "right" }],
          ]
          yAxis = { left = { min = 0 }, right = { min = 0, max = 100 } }
        }
      },
      {
        type = "metric", x = 12, y = 40, width = 12, height = 6
        properties = {
          title  = "Cache: CPU, memory, connections"
          region = var.region
          stat   = "Average"
          period = 60
          metrics = [
            ["AWS/ElastiCache", "EngineCPUUtilization", "CacheClusterId", local.cache_node, { label = "Engine CPU %" }],
            ["AWS/ElastiCache", "DatabaseMemoryUsagePercentage", "CacheClusterId", local.cache_node, { label = "Memory %" }],
            ["AWS/ElastiCache", "CurrConnections", "CacheClusterId", local.cache_node, { label = "Connections", yAxis = "right" }],
          ]
          yAxis = { left = { min = 0, max = 100 }, right = { min = 0 } }
        }
      },
    ]
  })
}
