import json

import boto3
import botocore
import pytest
import time
from conftest import Credentials, Role
from util import raises_boto_code

"""
This relies on two hard-coded accounts that have management acccess so that we can both change permissions and test them
Their trust policies allow for role hopping from the QA account. You must be signed into the QA account for this to work
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

# Reset the scps for an ou or an account to be just the default allow all
def reset_scps(TargetId):
    client = parent_client("organizations")
    # Start with baseline of only full access
    try:
        client.attach_policy(
            PolicyId=FULL_ACCESS_POLICY_ID,
            TargetId=TargetId # OU containing child
        )
    # It's ok if it's already attached
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "DuplicatePolicyAttachmentException":
            pass
        else:
            raise error

    scps = client.list_policies_for_target(
        TargetId=TargetId,
        Filter="SERVICE_CONTROL_POLICY"
    )["Policies"]
    # Detach anything other than full access scp
    for scp in scps:
        if scp["Arn"] == FULL_ACCESS_POICY_ARN:
            continue
        else:
            client.detach_policy(
                PolicyId=scp["Id"],
                TargetId=TargetId

            )
            client.delete_policy(
                PolicyId=scp["Id"]
            )
    time.sleep(10)

def is_in_parent(ParentId, TargetAccount, client):
    child_list = client.list_children(
        ParentId=ParentId,
        ChildType="ACCOUNT", # Hard coding for now due to the limited use. May pass as an argument if more flexibility is needed
    )
    for child in child_list["Children"]:
        if child["Id"] == TargetAccount:
            return True
    # Call again until there are no more results
    if child_list.get("NextToken"):
        is_in_parent(ParentId, TargetAccount, client)
    return False

        
# Reset the scps in ou and move the target account to it
def reset_parent():
    reset_scps(OU_ID)
    client = parent_client("organizations")
    if not is_in_parent(ParentId=OU_ID, TargetAccount=TARGET_ACCOUNT_ID, client=client):
        source_parent_id = client.list_parents(
            ChildId=TARGET_ACCOUNT_ID
        )["Parents"][0]["Id"]
        client.move_account(
            AccountId=TARGET_ACCOUNT_ID,
            SourceParentId=source_parent_id,
            DestinationParentId=OU_ID
        )

def delete_role(role_name):
    client = child_superclient("iam")
    for policy_name in client.list_role_policies(RoleName=role_name)['PolicyNames']:
            client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
    client.delete_role(
        RoleName=role_name,
    )


@pytest.fixture
def limited_role(request):
    reset_scps(TARGET_ACCOUNT_ID)
    reset_parent()
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
                "Principal": {"AWS": [PARENT_ACCOUNT_ID, TARGET_ACCOUNT_ID]},
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
            delete_role(role_name)
            role = client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy, indent=2),
        )['Role']
        else:
            raise error
    time.sleep(10)
    yield Role(
        role_name=role_name,
        arn=role['Arn'],
    )

    reset_scps(TARGET_ACCOUNT_ID)
    delete_role(role_name)


# Note the importance of passing limited_role first. Must assume a role in the target account
# before creating the test role so that the latter is also in the target account
def test_scp_on_target_account(limited_role):
    """
    Does an scp on the target account limit access. Yes it does!
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
                    "s3:DeleteBucket",
                    "s3:PutObject" # Implicitly denied by scp
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

    # Use parent client to limit by SCP and switch to limited role
    client = parent_client("organizations")
    scp = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": [
                    "s3:CreateBucket",
                    "s3:DeleteBucket"
                    # NOTE: No "s3:PutObject" 
                ],
                "Resource": "*",
            }
        ]
    }

    policy_name = "allow-put-and-delete-bucket-only"
    try:
        scp_id = client.create_policy(
            Content=json.dumps(scp, indent=2),
            Description="Limits actions in this account by implicit deny",
            Name=policy_name,
            Type="SERVICE_CONTROL_POLICY"
        )["Policy"]["PolicySummary"]["Id"]
    except botocore.exceptions.ClientError as error:
        # If another policy by the same name exists, we want to delete and creat a new one
        # To avoid unintentionally using a policy from an older test attempt
        if error.response["Error"]["Code"] == "DuplicatePolicyException":
            policies = client.list_policies(
                Filter="SERVICE_CONTROL_POLICY"
            )["Policies"]
            for policy in policies:
                if policy["Name"] == policy_name:
                    try:
                        client.delete_policy(
                            PolicyId=policy["Id"]
                        )
                        break
                    except botocore.exceptions.client_error as other_error:
                        if other_error == "PolicyInUse":
                            client.list_targets_for_policy(
                                PolicyId=policy["Id"]
                            )
                        else:
                            raise other_error

            scp_id = client.create_policy(
                Content=json.dumps(scp, indent=2),
                Description="Limits actions in this account by implicit deny",
                Name=policy_name,
                Type="SERVICE_CONTROL_POLICY"
            )["Policy"]["PolicySummary"]["Id"]
        else:
            raise error

    client.attach_policy(
        PolicyId=scp_id,
        TargetId=TARGET_ACCOUNT_ID
    )
    # Detach allow all policy 
    client.detach_policy(
        PolicyId=FULL_ACCESS_POLICY_ID,
        TargetId=TARGET_ACCOUNT_ID
    )

    client = parent_client("sts")
    credentials = client.assume_role(
        RoleArn=limited_role.arn,
        RoleSessionName="test",
        ExternalId=EXTERNAL_ID
    )["Credentials"]
    client = boto3.client(
        service_name="s3",
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )

    bucket_name = "scp-test-bucket-limited-role"
    time.sleep(10)
    client.create_bucket(
        Bucket=bucket_name
    )

    # Because put object is not in the SCP
    with raises_boto_code('AccessDenied'):
        client.put_object(
            Bucket=bucket_name,
            Key='text.txt',
            Body=b'Test Content',
        )

    client.delete_bucket(
        Bucket=bucket_name
    )   


def test_scp_on_source_account():
    """
    Does an scp on the account assuming the role have any impact?
    """
    pass
    

    
