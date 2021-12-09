import pytest
from uuid import uuid4
import logging
from util import raises_boto_code


LOG = logging.getLogger(__name__)


@pytest.fixture
def log_group(policy_executor):
    client = policy_executor.superclient('logs')
    log_group_name = f'iam-arn-test-{uuid4()}'

    client.create_log_group(logGroupName=log_group_name,
                            tags={'testing': 'tags'})
    LOG.info("Created log group: %s", log_group_name)

    yield log_group_name

    LOG.info("Deleting log group: %s", log_group_name)
    client.delete_log_group(logGroupName=log_group_name)


def test_whole_arn(policy_executor, log_group):
    """Test arn matching with log groups. This is a full match to the log group ARN"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )


def test_arn_with_stream(policy_executor, log_group):
    """Test arn matching with log groups. This test has a stream"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:log-stream:",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )


def test_arn_star_end(policy_executor, log_group):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see test above)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:*:",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )


def test_arn_star_resource(policy_executor, log_group):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see first test)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log_group:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    with raises_boto_code('AccessDeniedException'):
        client.list_tags_log_group(
            logGroupName=log_group
        )


def test_arn_star_resource_type(policy_executor, log_group):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see first test)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
