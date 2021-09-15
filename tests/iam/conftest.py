import boto3
from dataclasses import dataclass
import time
import json
import pytest
import logging
from uuid import uuid4


LOG = logging.getLogger(__name__)
logging.basicConfig(level='INFO')


@dataclass(frozen=True)
class Role:
    role_name: str
    arn: str


@dataclass(frozen=True)
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: str


class PolicyExecutor:
    POLICY_NAME = 'iam_validation_policy'

    def __init__(self, id, policy_cooldown_sec=30, region='us-east-1'):
        self.id = id
        self.policy_cooldown_sec = policy_cooldown_sec
        self.region = region
        self._check_aws_permissions()
        self.role = self.create_role()

    def _get_user_account_id(self):
        client = self.superclient('sts')
        identity_response = client.get_caller_identity()
        return identity_response['Account']

    def _check_aws_permissions(self):
        client = self.superclient('sts')
        identity_response = client.get_caller_identity()
        LOG.info("Verified AWS permissions using ARN: %s", identity_response['Arn'])

    def create_role(self) -> Role:
        client = self.superclient('iam')
        role_name = f'iam_validation_test_role_{self.id}'

        # delete it in case it existed already (it will be recreated)
        if self.does_role_exist(role_name):
            self.delete_role(role_name)

        # configure the role to be assumable by all members of the user's account.
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._get_user_account_id()},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        role = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy, indent=2),
        )['Role']

        LOG.info("Created role: %s", role)

        return Role(
            role_name=role_name,
            arn=role['Arn'],
        )

    def delete_role(self, role_name: str):
        LOG.info("Deleting role: %s", role_name)

        client = self.superclient('iam')
        for policy_name in client.list_role_policies(RoleName=role_name)['PolicyNames']:
            client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
        client.delete_role(
            RoleName=role_name,
        )

    def tag_role(self, tags: list):
        client = self.superclient('iam')
        client.tag_role(
            RoleName=self.role.role_name,
            Tags=tags
        )

    def does_role_exist(self, role_name: str):
        client = self.superclient('iam')
        try:
            client.get_role(RoleName=role_name)
            return True
        except client.exceptions.NoSuchEntityException:
            return False

    def cleanup(self):
        self.delete_role(self.role.role_name)

    def set_role_policy(self, policy):
        client = self.superclient('iam')
        client.put_role_policy(
            RoleName=self.role.role_name,
            PolicyName=self.POLICY_NAME,
            PolicyDocument=json.dumps(policy, indent=2),
        )

        # IAM is eventually consistent, so pause while the changes are replicated.
        # If this isn't done, there's a chance that subsequent actions will be
        # performed using an older policy document.
        if self.policy_cooldown_sec is not None:
            time.sleep(self.policy_cooldown_sec)

    def _assume_role(self) -> Credentials:
        client = self.superclient('sts')
        credentials = client.assume_role(
            RoleArn=self.role.arn,
            RoleSessionName=f'iam_validation_test_{uuid4()}',
        )['Credentials']

        return Credentials(
            access_key_id=credentials['AccessKeyId'],
            secret_access_key=credentials['SecretAccessKey'],
            session_token=credentials['SessionToken'],
        )

    def superclient(self, service_name):
        return boto3.client(
            service_name,
            region_name=self.region,
        )

    def roleclient(self, service_name):
        credentials = self._assume_role()
        return boto3.client(
            service_name,
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=self.region,
        )

    def superresource(self, service_name):
        return boto3.resource(
            service_name,
            region_name=self.region,
        )

    def roleresource(self, service_name):
        credentials = self._assume_role()
        return boto3.resource(
            service_name,
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=self.region,
        )


@pytest.fixture
def policy_executor(request):
    test_name = request.node.name
    executor = PolicyExecutor(id=test_name)

    yield executor

    executor.cleanup()
