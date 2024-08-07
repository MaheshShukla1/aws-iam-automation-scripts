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
    except iam.exceptions.EntityAlreadyExistsException:
        logging.error(f'User {user_name} already exists.')
    except Exception as e:
        logging.error(f'Error creating user {user_name}: {e}')

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
        if 'AccessKeyMetadata' in access_keys and access_keys['AccessKeyMetadata']:
            for key in access_keys['AccessKeyMetadata']:
                iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
                logging.info(f'Access key {key["AccessKeyId"]} for user {user_name} deleted successfully.')
        else:
            logging.info(f'No access keys found for user {user_name}.')

        # Delete inline policies
        inline_policies = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_policies.get('PolicyNames', []):
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            logging.info(f'Inline policy {policy_name} for user {user_name} deleted successfully.')

        # Delete attached policies
        attached_policies = iam.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
            logging.info(f'Policy {policy["PolicyArn"]} detached from user {user_name} successfully.')

        # Delete MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=user_name)
        if 'MFADevices' in mfa_devices and mfa_devices['MFADevices']:
            for mfa_device in mfa_devices['MFADevices']:
                iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa_device['SerialNumber'])
                iam.delete_virtual_mfa_device(SerialNumber=mfa_device['SerialNumber'])
                logging.info(f'MFA device {mfa_device["SerialNumber"]} for user {user_name} deleted successfully.')
        else:
            logging.info(f'No MFA devices found for user {user_name}.')

        # Finally delete the user
        response = iam.delete_user(UserName=user_name)
        logging.info(f'User {user_name} deleted successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'User {user_name} does not exist.')
    except Exception as e:
        logging.error(f'Error deleting the user {user_name}: {e}')

def create_role(role_name, trust_policy):
    if validate_json(json.dumps(trust_policy)):
        try:
            response = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            logging.info(f'Role {role_name} created successfully.')
            return response
        except iam.exceptions.EntityAlreadyExistsException:
            logging.error(f'Role {role_name} already exists.')
        except Exception as e:
            logging.error(f'Error creating role {role_name}: {e}')
    else:
        logging.error("Invalid trust policy JSON format")

def delete_role(role_name):
    try:
        # Detach all policies
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            logging.info(f'Policy {policy["PolicyArn"]} detached from role {role_name} successfully.')

        # Finally delete the role
        response = iam.delete_role(RoleName=role_name)
        logging.info(f'Role {role_name} deleted successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'Role {role_name} does not exist.')
    except Exception as e:
        logging.error(f'Error deleting role {role_name}: {e}')

def attach_role_policy(role_name, policy_arn):
    try:
        response = iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} attached to role {role_name} successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'Role {role_name} or policy {policy_arn} does not exist.')
    except Exception as e:
        logging.error(f'Error attaching policy to role {role_name}: {e}')

def detach_role_policy(role_name, policy_arn):
    try:
        response = iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} detached from role {role_name} successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'Role {role_name} or policy {policy_arn} does not exist.')
    except Exception as e:
        logging.error(f'Error detaching policy from role {role_name}: {e}')

def create_policy(policy_name, policy_document):
    if validate_json(json.dumps(policy_document)):
        try:
            response = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
            logging.info(f'Policy {policy_name} created successfully.')
            return response
        except iam.exceptions.EntityAlreadyExistsException:
            logging.error(f'Policy {policy_name} already exists.')
        except Exception as e:
            logging.error(f'Error creating policy {policy_name}: {e}')
    else:
        logging.error("Invalid policy document JSON format")

def delete_policy(policy_arn):
    try:
        # Check if the policy is attached to any roles or users
        attached_roles = iam.list_attached_policy_roles(PolicyArn=policy_arn)
        if attached_roles.get('AttachedRoles', []):
            logging.error(f'Policy {policy_arn} is attached to one or more roles. Please detach it before deleting.')
            return

        attached_users = iam.list_entities_for_policy(PolicyArn=policy_arn)
        if attached_users.get('Users', []):
            logging.error(f'Policy {policy_arn} is attached to one or more users. Please detach it before deleting.')
            return

        response = iam.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'Policy {policy_arn} does not exist.')
    except Exception as e:
        logging.error(f'Error deleting policy {policy_arn}: {e}')

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
        logging.info('Listing roles:')
        for role in response.get('Roles', []):
            logging.info(role)
    except Exception as e:
        logging.error(f'Error listing roles: {e}')

def list_policies():
    try:
        response = iam.list_policies()
        logging.info('Listing policies:')
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
    except iam.exceptions.EntityAlreadyExistsException:
        logging.error(f'Group {group_name} already exists.')
    except Exception as e:
        logging.error(f'Error creating group {group_name}: {e}')

def delete_group(group_name):
    try:
        # Detach all policies
        attached_policies = iam.list_attached_group_policies(GroupName=group_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
            logging.info(f'Policy {policy["PolicyArn"]} detached from group {group_name} successfully.')

        # Remove all users
        group_members = iam.get_group(GroupName=group_name)
        for user in group_members.get('Users', []):
            iam.remove_user_from_group(GroupName=group_name, UserName=user['UserName'])
            logging.info(f'User {user["UserName"]} removed from group {group_name}.')

        # Finally delete the group
        response = iam.delete_group(GroupName=group_name)
        logging.info(f'Group {group_name} deleted successfully.')
        return response
    except iam.exceptions.NoSuchEntityException:
        logging.error(f'Group {group_name} does not exist.')
    except Exception as e:
        logging.error(f'Error deleting group {group_name}: {e}')

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
            
            choice = int(input("Enter choice: "))
            
            if choice == 1:
                user_name = input("Enter username: ")
                create_user(user_name)
            elif choice == 2:
                list_users()
            elif choice == 3:
                user_name = input("Enter username: ")
                delete_user(user_name)
            elif choice == 4:
                role_name = input("Enter role name: ")
                trust_policy = json.loads(input("Enter trust policy JSON: "))
                create_role(role_name, trust_policy)
            elif choice == 5:
                role_name = input("Enter role name: ")
                delete_role(role_name)
            elif choice == 6:
                list_roles()
            elif choice == 7:
                role_name = input("Enter role name: ")
                policy_arn = input("Enter policy ARN: ")
                attach_role_policy(role_name, policy_arn)
            elif choice == 8:
                role_name = input("Enter role name: ")
                policy_arn = input("Enter policy ARN: ")
                detach_role_policy(role_name, policy_arn)
            elif choice == 9:
                policy_name = input("Enter policy name: ")
                policy_document = json.loads(input("Enter policy document JSON: "))
                create_policy(policy_name, policy_document)
            elif choice == 10:
                list_policies()
            elif choice == 11:
                policy_arn = input("Enter policy ARN: ")
                delete_policy(policy_arn)
            elif choice == 12:
                group_name = input("Enter group name: ")
                create_group(group_name)
            elif choice == 13:
                group_name = input("Enter group name: ")
                delete_group(group_name)
            elif choice == 14:
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            logging.error(f'Unexpected error: {e}')

if __name__ == "__main__":
    main()
