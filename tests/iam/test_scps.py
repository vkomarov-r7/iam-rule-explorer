import json

import boto3
import botocore
import pytest
from conftest import Credentials, Role

"""
This relies on two hard-coded accounts that have management acccess so that we can both change permissions and test them
Their trust policies allow for role hopping from the QA account. You might be signed into the QA account for this to work
"""

PARENT_ACCOUNT_ID = "745948225562"
TARGET_ACCOUNT_ID = "593324772711"
PARENT_ADMIN_ARN = f"arn:aws:iam::{PARENT_ACCOUNT_ID}:role/SCPTestMasterAccount"
CHILD_ADMIN_ARN = f"arn:aws:iam::{TARGET_ACCOUNT_ID}:role/SCPTestChildSuperRole"
EXTERNAL_ID = "scps-assume-role-tests"
# We use hard coded org and ou structure to avoid programmatically creating and tearing down accounts
# which is not recommended
OU_ID = "ou-5wjv-glg6vchq"
FULL_ACCESS_POLICY_ID = "p-FullAWSAccess"
FULL_ACCESS_POICY_ARN = f"arn:aws:organizations::aws:policy/service_control_policy/{FULL_ACCESS_POLICY_ID}"

def parent_client(service_name):
    client = boto3.client("sts")
    credentials = client.assume_role(
        RoleArn=PARENT_ADMIN_ARN,
        RoleSessionName="test",
        ExternalId=EXTERNAL_ID
    )['Credentials']

    return boto3.client(
        service_name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )

def child_superclient(service_name):
    client = parent_client("sts")
    credentials = client.assume_role(
        RoleArn=CHILD_ADMIN_ARN,
        RoleSessionName="Test",
        ExternalId=EXTERNAL_ID
    )["Credentials"]

    return boto3.client(
        service_name=service_name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )

# Create the scp that will limit the target role after superchild role creates and alters its permissions
def reset_scps():
    client = parent_client("organizations")
    # Start with baseline of only full access
    try:
        client.attach_policy(
            PolicyId=FULL_ACCESS_POLICY_ID,
            TargetId=OU_ID # OU containing child
        )
    # It's ok if it's already attached
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "DuplicatePolicyAttachmentException":
            pass
        else:
            raise error

    scps = client.list_policies_for_target(
        TargetId=OU_ID,
        Filter="SERVICE_CONTROL_POLICY"
    )["Policies"]
    # Detach anything other than full access scp
    for scp in scps:
        if scp["Arn"] == FULL_ACCESS_POICY_ARN:
            continue
        else:
            client.detach_policy(
                PolicyId=scp["Id"],
                TargetId=OU_ID
            )

@pytest.fixture
def limited_role(request):
    reset_scps()
    test_name = request.node.name
    role_name = f"scp_test_role{test_name.split('[')[0]}"
    # assume the child superclient role
    client = child_superclient("iam")
     # configure the role to be assumable by parent account
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": PARENT_ACCOUNT_ID},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    try:
        role = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy, indent=2),
        )['Role']
    # To avoid collisions with earlier tests that my have been partially run
    # Delete any roles by the same name that already exist
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "EntityAlreadyExists":
            client.delete_role(RoleName=role_name)
            role = client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy, indent=2),
            )['Role']
        else:
            raise error

    yield Role(
        role_name=role_name,
        arn=role['Arn'],
    )

    # Cleanup
    for policy_name in client.list_role_policies(RoleName=role_name)['PolicyNames']:
            client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
    client.delete_role(
        RoleName=role_name,
    )

    reset_scps()


# Note the importance of passing limited_role first. Must assume a role in the target account
# before creating the test role so that the latter is also in the target account
def test_scp_on_target_account(limited_role):
    """
    Does an scp on the target account limit access?
    """
    client = child_superclient("iam")
    # Identity policy that permits something generic
    idp = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "s3:CreateBucket",
                ],
                "Resource": "*",
            }
        ]
    }
    # Attach idp
    client.put_role_policy(
        RoleName=limited_role.role_name,
        PolicyName="AllowCreateBucket",
        PolicyDocument=json.dumps(idp, indent=2),
    )

    # Use parent client to switch to limited role
    client = parent_client("sts")
    credentials = client.assume_role(
        RoleArn=limited_role.arn,
        RoleSessionName="test",
        ExternalId=EXTERNAL_ID
    )["Credentials"]
    client = boto3.client(
        service_name=service_name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )

    # attempt action
    client.create_bucket(
        Bucket="scp_test_bucket"
    )

    # Switch to parent role
    # Create and attach scp to child account
    # SCP that limits permission to some different generic thing
    scp = {}
    # Remove allow all scp
    # Swith to target role
    # attempt action again

    # Should work without scp

    # Should not work with scp

def test_scp_on_source_account():
    """
    Does an scp on the account assuming the role have any impact?
    """
    pass
    

    
