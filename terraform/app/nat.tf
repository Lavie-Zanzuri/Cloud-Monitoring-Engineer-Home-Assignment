# ------------------------------------------------------------------------------
# NAT Gateway: outbound-only internet for the private app subnets.
# Lives in the app stack (not foundation) because it costs money by the hour:
# `terraform destroy` here removes it together with its route.
# One NAT in AZ a to halve the cost - in production: one per AZ.
# ------------------------------------------------------------------------------

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.project}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = local.f.public_subnet_ids[0]
  tags          = { Name = "${var.project}-nat" }
}

# Adds "0.0.0.0/0 -> NAT" to the private app route table created by foundation.
resource "aws_route" "private_app_to_nat" {
  route_table_id         = local.f.private_app_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}
