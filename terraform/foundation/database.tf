# ------------------------------------------------------------------------------
# PostgreSQL on RDS - in the private DB subnets, not reachable from the internet.
# The master password is generated and stored by AWS in Secrets Manager
# (manage_master_user_password), so it never appears in code, in Terraform state,
# or on anyone's laptop. App instances read it at boot through their IAM role.
# ------------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name        = "${var.project}-db-subnets"
  description = "Private DB subnets in both AZs (RDS requires at least two AZs)"
  subnet_ids  = aws_subnet.private_db[*].id
  tags        = { Name = "${var.project}-db-subnets" }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project}-db"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = 20
  storage_type      = "gp3"
  storage_encrypted = true # encryption at rest (AWS-managed KMS key)

  db_name                     = "phishing"
  username                    = "phishing_app"
  manage_master_user_password = true # AWS creates + stores the password in Secrets Manager

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  port                   = 5432

  # Cost-driven choices for this project - production values in comments.
  multi_az                   = false # prod: true (standby in the 2nd AZ, automatic failover)
  backup_retention_period    = 1     # prod: 7-35 days
  deletion_protection        = false # prod: true
  skip_final_snapshot        = true  # prod: false
  auto_minor_version_upgrade = true
  apply_immediately          = true

  tags = { Name = "${var.project}-db" }
}
