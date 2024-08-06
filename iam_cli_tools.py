import boto3
import logging
import json

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setup the IAM client
iam = boto3.client('iam')

def create_user(user_name):
    try:
        response = iam.create_user(UserName=user_name)
        logging.info(f'User {user_name} created successfully.')
        return response
    except Exception as e:
        logging.error(f'Error creating user: {user_name}: {e}')

def delete_user(user_name):
    try:
        response = iam.delete_user(
            UserName=user_name
        )
        logging.info(f'User {user_name} deleted successfully.')
        return response
    except Exception as e:
        logging.error(f'Error deleting the user {user_name}: {e}')

def create_role(role_name,assume_role_policy_document):
    """
    Create a new IAM Role

    :param role_name: Name of the policy to create
    :param assume_role_policy_document: Policy document for role assumption
    """
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        logging.info(f'Role: {role_name} created successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error creating role: {e}')

def delete_role(role_name):
    """
    Delete an existing IAM role.
    :param role_name: Name of the role to delete
    """
    try:
        response = iam.delete_role(RoleName=role_name)
        logging.info(f'Role {role_name} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting role: {role_name}: {e}')

def attach_role_policy(role_name,policy_arn):
    """
    Attach a policy to an IAM Role.

    :param role_name: Name of the role
    :param policy_arn: ArN of the policy to attach
    """
    try:
        response = iam.attach_role_policy(RoleName=role_name,PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} attach to role: {role_name} successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error attaching policy to role: {e}')

def detach_role_policy(role_name,policy_arn):
    """
    Detach a policy from an IAM Role

    :param role_name: Name of the role
    :param policy_arn: ARN of the policy to detach
    """
    try:
        response = iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        logging.info(f'Policy {policy_arn} detached from role: {role_name} successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error detaching policy from role: {e}')


def create_policy(policy_name,policy_document):
    """
    Create an IAM policy
    :param  policy_name: Name of the policy to create
    """