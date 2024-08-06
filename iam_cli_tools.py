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
        # Delete login profile if exists
        try:
            iam.delete_login_profile(UserName=user_name)
            logging.info(f'Login profile for user {user_name} deleted successfully.')
        except iam.exceptions.NoSuchEntityException:
            logging.info(f'No login profile for user {user_name}. Skipping.')

        # Delete access keys
        access_keys = iam.list_access_keys(UserName=user_name)
        for key in access_keys['AccessKeyMetadata']:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
            logging.info(f'Access key {key["AccessKeyId"]} for user {user_name} deleted successfully.')

        # Delete inline policies
        inline_policies = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_policies['PolicyNames']:
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            logging.info(f'Inline policy {policy_name} for user {user_name} deleted successfully.')

        # Delete attached policies
        attached_policies = iam.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies['AttachedPolicies']:
            iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
            logging.info(f'Policy {policy["PolicyArn"]} detached from user {user_name} successfully.')

        # Finally delete the user
        response = iam.delete_user(UserName=user_name)
        logging.info(f'User {user_name} deleted successfully.')
        return response
    except Exception as e:
        logging.error(f'Error deleting the user {user_name}: {e}')

def create_role(role_name, trust_policy):
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        logging.info(f'Role: {role_name} created successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error creating role: {e}')

def delete_role(role_name):
    try:
        response = iam.delete_role(RoleName=role_name)
        logging.info(f'Role {role_name} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting role: {role_name}: {e}')

def attach_role_policy(role_name, policy_arn):
    try:
        response = iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} attached to role: {role_name} successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error attaching policy to role: {e}')

def detach_role_policy(role_name, policy_arn):
    try:
        response = iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} detached from role: {role_name} successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error detaching policy from role: {e}')

def create_policy(policy_name, policy_document):
    try:
        response = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
        logging.info(f'Creating policy with name {policy_name}')
        return response
    except Exception as e:
        logging.error(f'Error creating policy: {e}')

def delete_policy(policy_arn):
    try:
        response = iam.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting policy: {e}')

def list_users():
    try:
        response = iam.list_users()
        logging.info('Listing users:')
        for user in response.get('Users', []):
            logging.info(user)
    except Exception as e:
        logging.error(f'Error listing users: {e}')

def list_roles():
    try:
        response = iam.list_roles()
        logging.info('Listing Roles:')
        for role in response.get('Roles', []):
            logging.info(role)
    except Exception as e:
        logging.error(f'Error listing roles: {e}')

def list_policies():
    try:
        response = iam.list_policies()
        logging.info('Listing policies.')
        for policy in response.get('Policies', []):
            logging.info(policy)
    except Exception as e:
        logging.error(f'Error listing policies: {e}')

def validate_json(json_str):
    try:
        json.loads(json_str)
        return True
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON: {e}")
        return False
    
def create_group(group_name):
    try:
        response = iam.create_group(GroupName=group_name)
        logging.info(f'Group {group_name} created successfully.')
        return response
    except Exception as e:
        logging.error(f'Error creating group: {group_name}: {e}')

def delete_group(group_name):
    try:
        # Detach all policies
        attached_policies = iam.list_attached_group_policies(GroupName=group_name)
        for policy in attached_policies['AttachedPolicies']:
            iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
            logging.info(f'Policy {policy["PolicyArn"]} detached from group {group_name} successfully.')

        # Remove all users
        group_members = iam.get_group(GroupName=group_name)
        for user in group_members['Users']:
            iam.remove_user_from_group(GroupName=group_name, UserName=user['UserName'])
            logging.info(f'User {user["UserName"]} removed from group {group_name}.')

        # Finally delete the group
        response = iam.delete_group(GroupName=group_name)
        logging.info(f'Group {group_name} deleted successfully.')
        return response
    except Exception as e:
        logging.error(f'Error deleting the group {group_name}: {e}')

documents = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "ec2:DescribeInstances",
                "ec2:RunInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:ec2:us-east-1:123456789012:instance/*",
                "arn:aws:s3:::s3bucketslearningproduction/*"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/Department": [
                        "Development",
                        "Production"
                    ]
                },
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {
                "AWS": "851725195108"
            },
            "Condition": {}
        }
    ]
}

def main():
    while True:
        try:
            print("\nSelect an option")
            print("1. Create User")
            print("2. List Users")
            print("3. Delete User")
            print("4. Create Role")
            print("5. Delete Role")
            print("6. List Roles")
            print("7. Attach Policy to Role")
            print("8. Detach Policy from Role")
            print("9. Create Policy")
            print("10. List Policies")
            print("11. Delete Policy")
            print("12. Create Group")
            print("13. Delete Group")
            print("14. Exit")

            choice = input("Enter your choice: ")

            if choice == '1':
                username = input("Enter username: ")
                create_user(username)
            elif choice == '2':
                list_users()
            elif choice == '3':
                username = input('Enter username: ')
                delete_user(username)
            elif choice == '4':
                role_name = input('Enter role name: ')
                if validate_json(json.dumps(trust_policy)):
                    create_role(role_name, trust_policy)
                else:
                    print("Invalid JSON format")
            elif choice == '5':
                delete_role(input("Enter role name: "))
            elif choice == '6':
                list_roles()
            elif choice == '7':
                role_name = input("Enter role name: ")
                policy_arn = input("Enter policy ARN: ")
                attach_role_policy(role_name, policy_arn)
            elif choice == '8':
                role_name = input("Enter role name: ")
                policy_arn = input("Enter policy ARN: ")
                detach_role_policy(role_name, policy_arn)
            elif choice == '9':
                policy_name = input("Enter policy name: ")
                if validate_json(json.dumps(documents)):
                    create_policy(policy_name, documents)
                else:
                    print("Invalid JSON format")
            elif choice == '10':
                list_policies()
            elif choice == '11':
                policy_arn = input("Enter policy ARN: ")
                delete_policy(policy_arn)
            elif choice == '12':
                group_name = input("Enter group name: ")
                create_group(group_name)
            elif choice == '13':
                group_name = input("Enter group name: ")
                delete_group(group_name)
            elif choice == '14':
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 14.")
        except Exception as e:
            logging.error(f'An error occurred: {e}')

if __name__ == "__main__":
    main()