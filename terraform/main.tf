# =============================================================================
# LAB DEVSECOPS - PERTEMUAN 11
# File: terraform/main.tf
#
# ⚠️  PERINGATAN: File ini SENGAJA mengandung kerentanan keamanan
#     untuk keperluan latihan praktikum Checkov.
#     JANGAN gunakan konfigurasi ini di lingkungan produksi!
#
# Jumlah kerentanan: ~15 temuan (CRITICAL + HIGH + MEDIUM)
# =============================================================================


terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"
}

variable "db_password" {
  description = "Password database RDS"
  type        = string
  sensitive   = true
}


provider "aws" {
  region = "ap-southeast-1"
}

# =============================================================================
# ❌ KERENTANAN 1: S3 Bucket tanpa enkripsi + ACL publik
# Check IDs: CKV_AWS_19, CKV_AWS_20, CKV_AWS_57, CKV_AWS_18
# =============================================================================
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket-dev"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.data.id
  target_prefix = "access-logs/"
}



# =============================================================================
# ❌ KERENTANAN 2: Security Group terbuka ke seluruh internet
# Check IDs: CKV_AWS_24, CKV_AWS_25, CKV2_AWS_12
# =============================================================================
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group untuk web server"

  ingress {
    description = "SSH hanya dari jaringan internal"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    description = "HTTPS dari internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =============================================================================
# ❌ KERENTANAN 3: IAM Policy dengan wildcard berbahaya
# Check IDs: CKV_AWS_40, CKV2_AWS_40
# =============================================================================
resource "aws_iam_policy" "admin" {
  name        = "app-limited-policy"
  description = "Limited permissions for application"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = [
        "${aws_s3_bucket.data.arn}/app-data/*"
      ]
    }]
  })
}

# ❌ IAM user dengan access key (seharusnya gunakan role)

resource "aws_iam_role" "app_role" {
  name = "app-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_role_policy" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.admin.arn
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "app-service-profile"
  role = aws_iam_role.app_role.name
}

# =============================================================================
# ❌ KERENTANAN 4: RDS dengan password hardcoded + publicly accessible
# Check IDs: CKV_AWS_17, CKV_AWS_27, CKV_AWS_129, CKV_AWS_157
# =============================================================================

resource "aws_db_instance" "main" {
  identifier        = "mydb-dev"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = "admin"
  password = var.db_password

  publicly_accessible    = false
  storage_encrypted      = true
  skip_final_snapshot    = false
  final_snapshot_identifier = "mydb-final-snapshot"

  deletion_protection      = true
  backup_retention_period  = 7
  multi_az                 = true
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot    = true

  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
}

# =============================================================================
# ❌ KERENTANAN 5: EC2 tanpa enkripsi EBS + IMDSv1
# Check IDs: CKV_AWS_8, CKV2_AWS_41, CKV_AWS_135
# =============================================================================

resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"

  iam_instance_profile = aws_iam_instance_profile.app_profile.name

  monitoring = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }
}

# =============================================================================
# ❌ KERENTANAN 6: CloudTrail tidak dienkripsi + tidak di semua region
# Check IDs: CKV_AWS_35, CKV_AWS_36, CKV2_AWS_10

# KMS Key untuk enkripsi log CloudTrail
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key untuk enkripsi CloudTrail"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}
# =============================================================================
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.data.id
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  is_multi_region_trail         = true
  enable_log_file_validation   = true
  include_global_service_events = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  depends_on = [
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]
}

# =============================================================================
# ❌ KERENTANAN 7: ElastiCache tanpa enkripsi at-rest dan in-transit
# Check IDs: CKV_AWS_28, CKV_AWS_29
# =============================================================================
resource "aws_elasticache_cluster" "cache" {
  cluster_id           = "my-cache"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

# CloudWatch Log Group untuk CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/main"
  retention_in_days = 90
}

# IAM Role untuk integrasi CloudTrail dengan CloudWatch
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# IAM Policy untuk mengirim log ke CloudWatch
resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}
