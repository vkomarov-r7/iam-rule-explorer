import pytest
from uuid import uuid4
import logging
from util import raises_boto_code


LOG = logging.getLogger(__name__)


@pytest.fixture
def s3_bucket(policy_executor):
    client = policy_executor.superclient('s3')
    s3 = policy_executor.superresource('s3')
    bucket_name = f'iam-validator-{uuid4()}'

    client.create_bucket(Bucket=bucket_name)
    LOG.info("Created bucket: %s", bucket_name)

    yield bucket_name

    s3.Bucket(bucket_name).objects.all().delete()
    LOG.info("Deleting bucket: %s", bucket_name)
    client.delete_bucket(Bucket=bucket_name)


def test_put_object_with_star(policy_executor, s3_bucket):
    """Test that a s3 policy with a star on the end of the resource block allows writing to the bucket."""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                ],
                "Resource": f"arn:aws:s3:::{s3_bucket}/*",
            }
        ]
    })

    client = policy_executor.roleclient('s3')
    client.put_object(
        Bucket=s3_bucket,
        Key='text.txt',
        Body=b'Test Content',
    )


def test_put_object_with_just_bucket_name(policy_executor, s3_bucket):
    """Test that a s3 policy with just a bucket name in the resource block disallows writing to the bucket."""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                ],
                "Resource": f"arn:aws:s3:::{s3_bucket}",
            }
        ]
    })

    client = policy_executor.roleclient('s3')
    with raises_boto_code('AccessDenied'):
        client.put_object(
            Bucket=s3_bucket,
            Key='text.txt',
            Body=b'Test Content',
        )
