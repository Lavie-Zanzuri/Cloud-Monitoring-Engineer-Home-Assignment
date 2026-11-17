# ------------------------------------------------------------------------------
# App package: Terraform zips ../../app and uploads it to a private S3 bucket.
# Instances download it with their IAM role - no GitHub token on the servers.
# The object key contains the zip's hash, so any code change produces a new key,
# a new launch template version and a rolling instance refresh.
# ------------------------------------------------------------------------------

data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../../app"
  output_path = "${path.module}/.build/app.zip"

  excludes = [
    "tests",
    "samples",
    "phishing.db",
    ".pytest_cache",
    "pytest.ini",
    "requirements-dev.txt",
    "__pycache__",
    "detector/__pycache__",
    "detector/checks/__pycache__",
    "web/__pycache__",
  ]
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true   # lets `terraform destroy` empty and delete it
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "app" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "releases/app-${data.archive_file.app.output_md5}.zip"
  source = data.archive_file.app.output_path
  etag   = data.archive_file.app.output_md5
}
