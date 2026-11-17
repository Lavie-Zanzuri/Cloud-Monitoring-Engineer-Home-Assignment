terraform {
  required_version = ">= 1.10" # needed for S3 native state locking (use_lockfile)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State lives in S3 (created once by hand - Terraform can't create the bucket
  # that stores its own state). Versioned bucket = we can roll back a broken state.
  backend "s3" {
    bucket       = "phishing-tfstate-207871833011"
    key          = "foundation/terraform.tfstate"
    region       = "eu-north-1"
    encrypt      = true
    use_lockfile = true # a lock file in S3 stops two applies running at once
  }
}

provider "aws" {
  region = var.region

  # Every resource gets these tags -> Cost Explorer can show what this project costs.
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "foundation"
      ManagedBy = "terraform"
    }
  }
}
