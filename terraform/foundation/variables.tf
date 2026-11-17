variable "region" {
  description = "AWS region. The Free plan account is limited to eu-north-1."
  type        = string
  default     = "eu-north-1"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "phishing-detector"
}

variable "vpc_cidr" {
  description = "Private IP range of the VPC (65,536 addresses)."
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "How many Availability Zones to spread across. 2 = survives losing one AZ."
  type        = number
  default     = 2
}

variable "db_instance_class" {
  description = "RDS size. db.t4g.micro = 2 vCPU (Graviton), 1 GB RAM - the cheapest option."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_engine_version" {
  description = "PostgreSQL major version. RDS picks the latest minor version."
  type        = string
  default     = "16"
}
