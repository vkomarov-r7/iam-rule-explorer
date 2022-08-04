import pytest
from uuid import uuid4
import logging
from util import raises_boto_code


LOG = logging.getLogger(__name__)

LOG_GROUP_NAME = f'iam-arn-test-{uuid4()}'
ACCOUNT_ID = "050283019178"
LOG_STREAM_NAME = f'iam-stream-arn-test-{uuid4()}'

@pytest.fixture
def log_group(policy_executor):
    client = policy_executor.superclient('logs')

    client.create_log_group(logGroupName=LOG_GROUP_NAME,
                            tags={'testing': 'tags'})

    LOG.info("Created log group: %s", LOG_GROUP_NAME)

    yield LOG_GROUP_NAME

    LOG.info("Deleting log group: %s", LOG_GROUP_NAME)
    client.delete_log_group(logGroupName=LOG_GROUP_NAME)
    

@pytest.fixture
def log_stream(policy_executor, log_group):
    client = policy_executor.superclient('logs')
    

    client.create_log_stream(logGroupName=log_group,
                            logStreamName=LOG_STREAM_NAME)

    LOG.info("Created log stream: %s", LOG_STREAM_NAME)

    yield LOG_STREAM_NAME

    LOG.info("Deleting log stream: %s", LOG_STREAM_NAME)
    client.delete_log_stream(
        logGroupName=log_group,
        logStreamName=LOG_STREAM_NAME
        )

@pytest.mark.parametrize("log_group_name", ["*", "log-group:foo:log-stream:*", " "])
def test_permitted_log_names(policy_executor, log_group_name):
    client = policy_executor.superclient('logs')
    with raises_boto_code("InvalidParameterException"):
        client.create_log_group(logGroupName=log_group_name)

@pytest.mark.parametrize("log_stream_name", ["*"])
def test_permitted_stream_names(policy_executor, log_group, log_stream_name):
    client = policy_executor.superclient('logs')
    with raises_boto_code("InvalidParameterException"):
        client.create_log_stream(logGroupName=log_group,
                                logStreamName=log_stream_name)


# Allows access to both log group and stream
@pytest.mark.parametrize(
    "pattern", [
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{LOG_GROUP_NAME}:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{LOG_GROUP_NAME}:log-stream:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:i*",
        f"arn:aws:logs:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:*:log-stream:*",
        f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group*"
    ],
    ids=[
        "test_whole_arn",
        "test_arn_with_stream_wildcard",
        "test_arn_star_resource",
        "test_arn_star_resource_type",
        "test_partial_group_name_arn",
        "test_arn_star_region",
        "test_star_in_group_and_stream_names",
        "log_group_star"
    ]
)
def test_matches_log_group_and_stream(policy_executor, log_group, log_stream, pattern):
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
                "Resource": pattern,
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


def test_full_stream_arn(policy_executor, log_group, log_stream):
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
                "Resource": f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{log_group}:log-stream:{log_stream}",
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


@pytest.mark.parametrize("incorrect_arn", [
    f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{LOG_GROUP_NAME}:burrito:"
    f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:foo:burrito:"
    f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:foo:{LOG_STREAM_NAME}:"
    ])
def test_arn_matches_neither(policy_executor, log_group, log_stream, incorrect_arn):
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
                "Resource": incorrect_arn,
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

# Matches log group but not stream
@pytest.mark.parametrize("pattern", [
    f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{LOG_GROUP_NAME}:log-stream:",
    f"arn:aws:logs:us-east-1:{ACCOUNT_ID}:log-group:{LOG_GROUP_NAME}:*:",  # Note the ending colon
    ],
    # Matches ids in iam-rule-explorer
    ids=[
        "test_arn_with_partial_stream",
        "test_arn_star_end",
    ]
    )
def test_matches_log_group_but_not_stream(policy_executor, log_group, log_stream, pattern):
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
                "Resource": pattern,
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