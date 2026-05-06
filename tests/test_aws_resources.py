"""
Tests for AWS Resources Detection in reStalker
Tests for Amazon ARN, S3 Buckets, IAM Access Keys, EC2 Instances, and RDS Endpoints
"""
import pytest
from restalker import reStalker
from restalker.restalker import (
    AWS_ARN, S3_Bucket, AWS_Access_Key, EC2_Instance, RDS_Endpoint
)


class TestAWSARN:
    """Test Amazon Resource Name (ARN) detection"""
    
    def test_valid_arn_s3(self):
        """Test valid S3 ARN"""
        arn = "arn:aws:s3:::my-bucket/my-object"
        assert AWS_ARN.isvalid(arn) is True
    
    def test_valid_arn_iam(self):
        """Test valid IAM ARN"""
        arn = "arn:aws:iam::123456789012:user/Development/product_1/*"
        assert AWS_ARN.isvalid(arn) is True
    
    def test_valid_arn_ec2(self):
        """Test valid EC2 ARN"""
        arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
        assert AWS_ARN.isvalid(arn) is True
    
    def test_valid_arn_rds(self):
        """Test valid RDS ARN"""
        arn = "arn:aws:rds:us-east-1:123456789012:db:mydbinstance"
        assert AWS_ARN.isvalid(arn) is True
    
    def test_valid_arn_aws_cn(self):
        """Test valid ARN with aws-cn partition"""
        arn = "arn:aws-cn:s3:::my-bucket"
        assert AWS_ARN.isvalid(arn) is True
    
    def test_invalid_arn_missing_parts(self):
        """Test invalid ARN with missing parts"""
        arn = "arn:aws:s3"
        assert AWS_ARN.isvalid(arn) is False
    
    def test_invalid_arn_bad_partition(self):
        """Test invalid ARN with invalid partition"""
        arn = "arn:invalid:s3:::my-bucket"
        assert AWS_ARN.isvalid(arn) is False


class TestS3Bucket:
    """Test S3 Bucket detection"""
    
    def test_valid_s3_bucket_name(self):
        """Test valid S3 bucket name"""
        bucket = "my-bucket-123"
        assert S3_Bucket.isvalid(bucket) is True
    
    def test_valid_s3_bucket_with_s3_protocol(self):
        """Test S3 bucket URL with s3:// protocol"""
        bucket = "s3://my-bucket"
        assert S3_Bucket.isvalid(bucket) is True
    
    def test_valid_s3_bucket_domain_format(self):
        """Test S3 bucket in domain format"""
        bucket = "my-bucket.s3.amazonaws.com"
        assert S3_Bucket.isvalid(bucket) is True
    
    def test_valid_s3_bucket_with_region(self):
        """Test S3 bucket with region in domain"""
        bucket = "my-bucket.s3.us-west-2.amazonaws.com"
        assert S3_Bucket.isvalid(bucket) is True
    
    def test_invalid_s3_bucket_too_short(self):
        """Test invalid S3 bucket name (too short)"""
        bucket = "ab"
        assert S3_Bucket.isvalid(bucket) is False
    
    def test_invalid_s3_bucket_too_long(self):
        """Test invalid S3 bucket name (too long)"""
        bucket = "a" * 64
        assert S3_Bucket.isvalid(bucket) is False
    
    def test_invalid_s3_bucket_starts_with_dash(self):
        """Test invalid S3 bucket name (starts with dash)"""
        bucket = "-my-bucket"
        assert S3_Bucket.isvalid(bucket) is False
    
    def test_invalid_s3_bucket_consecutive_dots(self):
        """Test invalid S3 bucket name (consecutive dots)"""
        bucket = "my..bucket"
        assert S3_Bucket.isvalid(bucket) is False


class TestAWSAccessKey:
    """Test AWS Access Key detection"""
    
    def test_valid_access_key(self):
        """Test valid AWS Access Key"""
        key = "AKIAIOSFODNN7EXAMPLE"
        assert AWS_Access_Key.isvalid(key) is True
    
    def test_valid_access_key_variations(self):
        """Test valid AWS Access Key variations"""
        key = "AKIA1234567890ABCDEF"
        assert AWS_Access_Key.isvalid(key) is True
    
    def test_invalid_access_key_wrong_prefix(self):
        """Test invalid Access Key with wrong prefix"""
        key = "AKBA1234567890ABCDEF"
        assert AWS_Access_Key.isvalid(key) is False
    
    def test_invalid_access_key_too_short(self):
        """Test invalid Access Key (too short)"""
        key = "AKIA123456"
        assert AWS_Access_Key.isvalid(key) is False
    
    def test_invalid_access_key_too_long(self):
        """Test invalid Access Key (too long)"""
        key = "AKIA1234567890ABCDEFGH"
        assert AWS_Access_Key.isvalid(key) is False


class TestEC2Instance:
    """Test EC2 Instance ID detection"""
    
    def test_valid_ec2_instance_short(self):
        """Test valid EC2 Instance ID (8 hex chars)"""
        instance_id = "i-1234567a"
        assert EC2_Instance.isvalid(instance_id) is True
    
    def test_valid_ec2_instance_long(self):
        """Test valid EC2 Instance ID (17 hex chars)"""
        instance_id = "i-1234567890abcdef0"
        assert EC2_Instance.isvalid(instance_id) is True
    
    def test_invalid_ec2_instance_wrong_prefix(self):
        """Test invalid Instance ID (wrong prefix)"""
        instance_id = "x-1234567890abcdef0"
        assert EC2_Instance.isvalid(instance_id) is False
    
    def test_invalid_ec2_instance_wrong_length(self):
        """Test invalid Instance ID (wrong length)"""
        instance_id = "i-123456"
        assert EC2_Instance.isvalid(instance_id) is False
    
    def test_invalid_ec2_instance_non_hex(self):
        """Test invalid Instance ID (non-hexadecimal)"""
        instance_id = "i-1234567G"
        assert EC2_Instance.isvalid(instance_id) is False


class TestRDSEndpoint:
    """Test RDS Endpoint detection"""
    
    def test_valid_rds_endpoint(self):
        """Test valid RDS endpoint"""
        endpoint = "mydbinstance.c9akciq32.us-east-1.rds.amazonaws.com"
        assert RDS_Endpoint.isvalid(endpoint) is True
    
    def test_valid_rds_endpoint_different_region(self):
        """Test valid RDS endpoint with different region"""
        endpoint = "mydb.abcdefghij.eu-west-1.rds.amazonaws.com"
        assert RDS_Endpoint.isvalid(endpoint) is True
    
    def test_invalid_rds_endpoint_missing_parts(self):
        """Test invalid RDS endpoint (missing parts)"""
        endpoint = "mydbinstance.rds.amazonaws.com"
        assert RDS_Endpoint.isvalid(endpoint) is False
    
    def test_invalid_rds_endpoint_wrong_domain(self):
        """Test invalid RDS endpoint (wrong domain)"""
        endpoint = "mydbinstance.c9akciq32.us-east-1.rds.example.com"
        assert RDS_Endpoint.isvalid(endpoint) is False


class TestAWSResourcesExtraction:
    """Test extraction of AWS resources from text"""
    
    def test_extract_arn_from_text(self):
        """Test extracting ARN from text"""
        stalker = reStalker(aws_arn=True)
        text = "The resource ARN is arn:aws:s3:::my-bucket and it's important"
        results = list(stalker.parse(text))
        
        assert len(results) > 0
        arns = [r for r in results if isinstance(r, AWS_ARN)]
        assert len(arns) > 0
        assert "arn:aws:s3:::my-bucket" in [a.value for a in arns]
    
    def test_extract_s3_bucket_from_url(self):
        """Test extracting S3 bucket URL from text"""
        stalker = reStalker(s3_bucket=True)
        text = "Upload files to s3://my-bucket-data or use my-bucket-data.s3.amazonaws.com"
        results = list(stalker.parse(text))
        
        s3_buckets = [r for r in results if isinstance(r, S3_Bucket)]
        assert len(s3_buckets) > 0
    
    def test_extract_access_key_from_text(self):
        """Test extracting Access Key from text"""
        stalker = reStalker(aws_access_key=True)
        text = "Please use access key AKIAIOSFODNN7EXAMPLE for authentication"
        results = list(stalker.parse(text))
        
        access_keys = [r for r in results if isinstance(r, AWS_Access_Key)]
        assert len(access_keys) > 0
        assert "AKIAIOSFODNN7EXAMPLE" in [k.value for k in access_keys]
    
    def test_extract_ec2_instance_from_text(self):
        """Test extracting EC2 Instance ID from text"""
        stalker = reStalker(ec2_instance=True)
        text = "The instance i-1234567890abcdef0 is running and the instance i-0987654a has issues"
        results = list(stalker.parse(text))
        
        instances = [r for r in results if isinstance(r, EC2_Instance)]
        assert len(instances) > 0
    
    def test_extract_rds_endpoint_from_text(self):
        """Test extracting RDS endpoint from text"""
        stalker = reStalker(rds_endpoint=True)
        text = "Connect to mydb.abcdefghij.us-east-1.rds.amazonaws.com for database access"
        results = list(stalker.parse(text))
        
        endpoints = [r for r in results if isinstance(r, RDS_Endpoint)]
        assert len(endpoints) > 0
        assert "mydb.abcdefghij.us-east-1.rds.amazonaws.com" in [e.value for e in endpoints]
    
    def test_extract_all_aws_resources(self):
        """Test extracting all AWS resources at once"""
        stalker = reStalker(
            aws_arn=True,
            s3_bucket=True,
            aws_access_key=True,
            ec2_instance=True,
            rds_endpoint=True
        )
        
        text = """
        ARN: arn:aws:iam::123456789012:user/Development
        Bucket: s3://my-data-bucket
        Access Key: AKIAIOSFODNN7EXAMPLE
        Instance: i-1234567890abcdef0
        Database: mydb.c9akciq32.us-east-1.rds.amazonaws.com
        """
        
        results = list(stalker.parse(text))
        
        # Filter out other detected items
        aws_arns = [r for r in results if isinstance(r, AWS_ARN)]
        s3_buckets = [r for r in results if isinstance(r, S3_Bucket)]
        access_keys = [r for r in results if isinstance(r, AWS_Access_Key)]
        instances = [r for r in results if isinstance(r, EC2_Instance)]
        endpoints = [r for r in results if isinstance(r, RDS_Endpoint)]
        
        assert len(aws_arns) > 0
        assert len(s3_buckets) > 0
        assert len(access_keys) > 0
        assert len(instances) > 0
        assert len(endpoints) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
