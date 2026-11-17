# The app stack reads these through terraform_remote_state.

output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "azs" {
  value = local.azs
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_app_subnet_ids" {
  value = aws_subnet.private_app[*].id
}

output "private_db_subnet_ids" {
  value = aws_subnet.private_db[*].id
}

output "private_app_route_table_id" {
  description = "The app stack adds the NAT route to this table."
  value       = aws_route_table.private_app.id
}

# ---------- security groups ----------

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

# ---------- database ----------

output "db_address" {
  description = "Hostname the app connects to (never an IP - it can change on failover)."
  value       = aws_db_instance.main.address
}

output "db_port" {
  value = aws_db_instance.main.port
}

output "db_name" {
  value = aws_db_instance.main.db_name
}

output "db_master_secret_arn" {
  description = "Secrets Manager secret holding the DB username and password (created by RDS)."
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "db_instance_id" {
  description = "Used to stop/start the DB between work sessions."
  value       = aws_db_instance.main.identifier
}
