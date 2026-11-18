# ------------------------------------------------------------------------------
# ElastiCache (Valkey - the open-source Redis fork AWS now recommends; same
# protocol, the app uses the standard redis client).
# Caches scan results by email hash: the same campaign email is analysed once.
#
# Lives in the app stack (not foundation) so `destroy` removes it with the rest
# of the hourly-billed resources. It holds nothing that can't be recomputed.
# ------------------------------------------------------------------------------

# Same pattern as the database: only the app instances can reach it.
resource "aws_security_group" "cache" {
  name        = "${var.project}-cache-sg"
  description = "Cache: Valkey only from the app instances"
  vpc_id      = local.f.vpc_id
  tags        = { Name = "${var.project}-cache-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "cache_from_app" {
  security_group_id            = aws_security_group.cache.id
  description                  = "Valkey, only from the app instances"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = local.f.app_security_group_id
}

# app-sg (in foundation) has tight egress, so the instances need an explicit way out
# to the cache. The rule is created here because the cache SG only exists in this stack.
resource "aws_vpc_security_group_egress_rule" "app_to_cache" {
  security_group_id            = local.f.app_security_group_id
  description                  = "Valkey to the cache"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.cache.id
}

# Private DB subnets: no route to the internet at all, like RDS.
resource "aws_elasticache_subnet_group" "cache" {
  name       = "${var.project}-cache"
  subnet_ids = local.f.private_db_subnet_ids
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "${var.project}-cache"
  description          = "Scan result cache"
  engine               = "valkey"
  engine_version       = "8.0"
  node_type            = "cache.t4g.micro"   # smallest node: 2 vCPU, 0.5 GB
  port                 = 6379

  # One node, no replica: a cache can be lost and rebuilt, so we don't pay for HA.
  # prod: num_cache_clusters = 2 + automatic_failover_enabled + multi_az_enabled.
  num_cache_clusters         = 1
  automatic_failover_enabled = false
  multi_az_enabled           = false

  subnet_group_name  = aws_elasticache_subnet_group.cache.name
  security_group_ids = [aws_security_group.cache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true   # TLS - the app connects with rediss://

  snapshot_retention_limit = 0        # nothing worth backing up
  apply_immediately        = true

  tags = { Name = "${var.project}-cache" }
}
