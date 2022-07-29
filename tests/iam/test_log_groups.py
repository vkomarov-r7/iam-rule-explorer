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
    

@pytest.fixture
def log_stream(policy_executor, log_group):
    client = policy_executor.superclient('logs')
    log_stream_name = f'iam-stream-arn-test-{uuid4()}'

    client.create_log_stream(logGroupName=log_group,
                            logStreamName=log_stream_name)

    LOG.info("Created log stream: %s", log_stream_name)

    yield log_stream_name

    LOG.info("Deleting log stream: %s", log_stream_name)
    client.delete_log_stream(
        logGroupName=log_group,
        logStreamName=log_stream_name
        )


def test_whole_arn(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. This is a full match to the log group ARN"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
        logGroupName=log_group,
        logStreamName=log_stream
    )


def test_full_stream_does_not_match_full_log(policy_executor, log_group, log_stream):
    """While access to a group arn can permit access to the streams therein, access to a stream does not permit access to the group"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:log-stream:{log_stream}",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.get_log_events(
        logGroupName=log_group,
        logStreamName=log_stream
    )
    with raises_boto_code('AccessDeniedException'):
        client.list_tags_log_group(
            logGroupName=log_group
        )


def test_arn_with_partial_stream(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. This test has a stream. Does not provide access to the stream due to lack of wildcard"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:log-stream:",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    with raises_boto_code('AccessDeniedException'):
        client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )

def test_arn_with_stream_wildcard(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. This test has a stream. Provides access to"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:log-stream:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream
        )


def test_arn_with_incorrect_stream(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. This test has an incorrect word instead of log-stream"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:burrito:",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    with raises_boto_code('AccessDeniedException'):
        client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream
        )
    with raises_boto_code('AccessDeniedException'):
        client.list_tags_log_group(
            logGroupName=log_group
        )


def test_arn_star_end(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see test above)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:{log_group}:*:",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    with raises_boto_code('AccessDeniedException'):
        client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )


def test_arn_star_resource(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see first test)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )


def test_arn_star_resource_type(policy_executor, log_group, log_stream):
    """Test arn matching with log groups. The log group arn in question ends in log-stream (no star, see first test)"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )


def test_arn_star_region(policy_executor, log_group, log_stream):
    """Test arn matching with log groups"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )


def test_partial_group_name_arn(policy_executor, log_group, log_stream):
    """Test arn matching with log groups"""
    policy_executor.set_role_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "logs:List*",
                    "logs:GetLogEvents"
                ],
                "Resource": f"arn:aws:logs:us-east-1:050283019178:log-group:i*",
            }
        ]
    })

    client = policy_executor.roleclient('logs')
    client.list_tags_log_group(
        logGroupName=log_group
    )
    client.get_log_events(
                logGroupName=log_group,
                logStreamName=log_stream
            )
