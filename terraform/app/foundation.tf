# Read the outputs of the foundation stack (VPC, subnets, SGs, DB) straight from
# its state file - no IDs copied by hand.

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "phishing-tfstate-207871833011"
    key    = "foundation/terraform.tfstate"
    region = "eu-north-1"
  }
}

data "aws_caller_identity" "current" {}

locals {
  f = data.terraform_remote_state.foundation.outputs
}
