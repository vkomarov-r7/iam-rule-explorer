import botocore
import boto3
from conftest import Credentials

"""
This relies on two hard-coded accounts that have management acccess so that we can both change permissions and test them
Their trust policies allow for role hopping from the QA account. You might be signed into the QA account for this to work
"""


PARENT_ADMIN_ARN = "arn:aws:iam::745948225562:role/SCPTestMasterAccount"
CHILD_ADMIN_ARN = "arn:aws:iam::593324772711:role/SCPTestChildSuperRole"
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
    client.attach_policy(
        PolicyId=FULL_ACCESS_POLICY_ID,
        TargetId=OU_ID # OU containing child
    )
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


def test_scp_on_target_account_limits_assumed_role_actions():
    """
    Does an scp on the target account limit access?
    """
    reset_scps()


def test_scp_on_source_account():
    """
    Does an scp on the account assuming the role have any impact?
    """
    pass
    

    
