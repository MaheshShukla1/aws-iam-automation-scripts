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
    :param policy_document: Policy Document
    """
    try:
        response = iam.create_policy(PolicyName=policy_name,PolicyDocument=policy_document)
        logging.info(f'Creating policy with name {policy_name}')
        return response
    except Exception as e:
        logging.error(f'Error creating policy: {e}')
        
def delete_policy(policy_arn):
    """
    Delete an existing IAM policy

    :param policy_arn: ARN of the policy to delete
    """
    try:
        response = iam.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting policy: {e}')

def list_users():
    """
    List all IAM Users.
    """
    try:
        response = iam.list_users()
        logging.info('Listing users:')
        for user in response.get('Users',[]):
            logging.info(user)
    except Exception as e:
        logging.error(f'Error listing users: {e}')

def list_roles():
    """
    List all IAM Roles
    """
    try:
        response = iam.client_list_roles()
        logging.info('Listing Roles:')
        for role in response.get('Roles',[]):
            logging.info(role)
    except Exception as e:
        logging.error(f'Error listing roles: {e}')

def list_policies():
    """
    List All IAM policies.
    """
    try:
        response = iam.list_policies()
        logging.info('Listing policies.')
        for policy in response.get('Policies',[]):
            logging.info(policy)
    except Exception as e:
        logging.error(f'Error listing policies: {e}')


def validate_json(json_str):
    """
    Validate a json string
    
    :param json_str: JSON strong to validates
    :raises: ValueError if json is valid
    """
    try:
        json.loads(json_str)
    except Exception as e:
        logging.error(f'Invalid JSON: {e}')

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

def main():
    """
    Main function to handle user input and execute corresponding IAM operations.
    """
    while True:
        print("\n Select an option")
        print("1. Create User")
        print("2. List User")
        print("3. Delete User")
        print("4. Create Role")
        print("5. Delete Role")
        print("6. List Roles")
        print("7. Attach Policy to Role")
        print("8. Detach Policy to Role")
        print("9. Create Policy")
        print("10. List policies")
        print("11. Delete Policy")
        print("Exit")

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
            role_name = input('Enter rolename: ')
            assume_role_policy_document = input('Enter assume role policy document JSON: ')
            validate_json(assume_role_policy_document)
            create_role(role_name,json.loads(assume_role_policy_document))
        elif choice == '5':
            list_roles()
        elif choice == '6':
            list_policies()
        elif choice == '7':
            role_name = input("Enter rolename: ")
            policy_arn = input("Enter policy ARN: ")
            attach_role_policy(role_name,policy_arn)
        elif choice == '8':
            role_name = input('Enter rolename: ')
            policy_arn = input('Enter policy ')
            detach_role_policy(role_name,policy_arn)
        elif choice == '9':
            policy_name = input('Enter policyname: ')
            policy_document = documents
            validate_json(policy_document)
            create_policy(policy_name,json.loads(policy_document))
        elif choice == '10':
            list_policies()
        elif choice == '11':
            policy_arn = input('Enter policy ARN: ')
            delete_policy(policy_arn)
        elif choice == '12':
            print('Exiting...')
            break
        else:
            print('Invalid choice')

if __name__ == "__main__":
    main()

