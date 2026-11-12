resource "aws_s3_bucket" "statements" {
  bucket = "kavachbank-statements"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "kavachbank-admin"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "ledger" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  storage_encrypted   = false
  publicly_accessible = true
}
