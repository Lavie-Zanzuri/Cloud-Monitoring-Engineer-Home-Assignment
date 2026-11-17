# ------------------------------------------------------------------------------
# Network: one VPC across 2 Availability Zones, three subnet tiers per AZ.
#
#   tier         AZ a           AZ b           route to the internet
#   public       10.0.1.0/24    10.0.2.0/24    Internet Gateway (both ways)
#   private app  10.0.11.0/24   10.0.12.0/24   NAT Gateway (out only) - added by the app stack
#   private db   10.0.21.0/24   10.0.22.0/24   none at all
# ------------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true   # instances can resolve names (RDS endpoint, AWS APIs)
  enable_dns_hostnames = true   # required for RDS and for SSM to work in private subnets

  tags = { Name = "${var.project}-vpc" }
}

# Lock down the VPC's default security group (no rules = nothing allowed).
# Anything accidentally launched without an explicit SG gets no network access.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-default-locked" }
}

# ---------- subnets ----------
# cidrsubnet("10.0.0.0/16", 8, N) = 10.0.N.0/24

resource "aws_subnet" "public" {
  count             = var.az_count
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 1 + count.index)

  # Only the ALB and NAT live here and they get their addresses from AWS,
  # so nothing launched here should get a public IP by accident.
  map_public_ip_on_launch = false

  tags = { Name = "${var.project}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private_app" {
  count             = var.az_count
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 11 + count.index)

  tags = { Name = "${var.project}-app-${local.azs[count.index]}", Tier = "private-app" }
}

resource "aws_subnet" "private_db" {
  count             = var.az_count
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 21 + count.index)

  tags = { Name = "${var.project}-db-${local.azs[count.index]}", Tier = "private-db" }
}

# ---------- internet gateway + public routing ----------

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------- private app routing ----------
# No internet route here on purpose: the app stack adds "0.0.0.0/0 -> NAT" when it
# creates the NAT Gateway, and removes it on destroy (NAT only costs money while up).

resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-private-app-rt" }
}

resource "aws_route_table_association" "private_app" {
  count          = var.az_count
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private_app.id
}

# ---------- private db routing ----------
# Only the implicit "local" route: the database can talk inside the VPC and nowhere else.

resource "aws_route_table" "private_db" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-private-db-rt" }
}

resource "aws_route_table_association" "private_db" {
  count          = var.az_count
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private_db.id
}

# ---------- S3 gateway endpoint (free) ----------
# Instances download the app package from S3 over the AWS network instead of
# through the NAT Gateway, which charges per GB.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_app.id]

  tags = { Name = "${var.project}-s3-endpoint" }
}
