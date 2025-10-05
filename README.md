# 🚀 AWS IAM Automation Scripts

This repository provides a comprehensive suite of scripts for automating AWS Identity and Access Management (IAM) tasks using Python with Boto3 and AWS CLI. These automation scripts cover the creation and management of IAM policies, roles, and their attachments, making it easier to manage AWS IAM resources efficiently.

## 📂 **Table of Contents**
1. [Python Scripts](#python-scripts)
    - [Create User](#create-user)
    - [Delete User](#delete-user)
    - [Create Group](#create-group)
    - [Delete Group](#delete-group)
    - [Create Policy](#create-policy)
    - [Delete Policy](#delete-policy)
    - [Attach User Policy](#attach-user-policy)
    - [Detach User Policy](#detach-user-policy)
    - [Create Role](#create-role)
    - [Delete Role](#delete-role)
    - [Attach Role Policy](#attach-role-policy)
    - [Detach Role Policy](#detach-role-policy)
2. [Shell Script](#shell-script)
    
    - `iam_automation.sh`
3. [Setup](#setup)
    
    - [Install Python Packages](#install-python-packages)
    - [Configure AWS Credentials](#configure-aws-credentials)
4. [Notes](#notes)
    
5. [Contact](#contact)
   
## 🐍 **Python Scripts**
### Create User
Automate the creation of an IAM User.
```python
import boto3
def create_user(user_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_user(UserName=user_name)
        print(f'User {user_name} created successfully.')
        print(response)
    except Exception as e:
        print(f'Error creating user: {e}')

create_user('Alice')
```
**Usage:**
```bash
   python create_user.py
```

### Delete User

Easily automate the deletion of an IAM User.
```python
import boto3
import botocore.exceptions
import logging
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_iam_client(profile_name=None, region_name='us-east-1'):
    """Create and return a Boto3 IAM client."""
    try:
        if profile_name:
            boto3.setup_default_session(profile_name=profile_name)
        return boto3.client('iam', region_name=region_name)
    except botocore.exceptions.BotoCoreError as e:
        logging.error(f'Error creating IAM client: {e}')
        sys.exit(1)

def delete_user_completely(iam, user):
    """Fully delete an IAM user with all attached entities."""
    try:
        iam.get_user(UserName=user)
        logging.info(f'Found user: {user}')

        # 1. Delete access keys
        keys = iam.list_access_keys(UserName=user).get('AccessKeyMetadata', [])
        for key in keys:
            iam.delete_access_key(UserName=user, AccessKeyId=key['AccessKeyId'])
            logging.info(f"Deleted access key: {key['AccessKeyId']}")

        # 2. Delete login profile
        try:
            iam.delete_login_profile(UserName=user)
            logging.info("Deleted login profile")
        except iam.exceptions.NoSuchEntityException:
            pass

        # 3. Delete inline policies
        inline_policies = iam.list_user_policies(UserName=user).get('PolicyNames', [])
        for policy_name in inline_policies:
            iam.delete_user_policy(UserName=user, PolicyName=policy_name)
            logging.info(f"Deleted inline policy: {policy_name}")

        # 4. Detach managed policies
        attached_policies = iam.list_attached_user_policies(UserName=user).get('AttachedPolicies', [])
        for policy in attached_policies:
            iam.detach_user_policy(UserName=user, PolicyArn=policy['PolicyArn'])
            logging.info(f"Detached managed policy: {policy['PolicyName']}")

        # 5. Deactivate & delete MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=user).get('MFADevices', [])
        for mfa in mfa_devices:
            serial = mfa['SerialNumber']
            iam.deactivate_mfa_device(UserName=user, SerialNumber=serial)
            iam.delete_virtual_mfa_device(SerialNumber=serial)
            logging.info(f"Deleted MFA device: {serial}")

        # 6. Delete SSH public keys
        ssh_keys = iam.list_ssh_public_keys(UserName=user).get('SSHPublicKeys', [])
        for ssh in ssh_keys:
            iam.delete_ssh_public_key(UserName=user, SSHPublicKeyId=ssh['SSHPublicKeyId'])
            logging.info(f"Deleted SSH public key: {ssh['SSHPublicKeyId']}")

        # 7. Delete service-specific credentials (e.g., CodeCommit)
        service_creds = iam.list_service_specific_credentials(UserName=user).get('ServiceSpecificCredentials', [])
        for cred in service_creds:
            iam.delete_service_specific_credential(UserName=user, ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId'])
            logging.info(f"Deleted service-specific credential: {cred['ServiceSpecificCredentialId']}")

        # 8. Delete signing certificates
        certs = iam.list_signing_certificates(UserName=user).get('Certificates', [])
        for cert in certs:
            iam.delete_signing_certificate(UserName=user, CertificateId=cert['CertificateId'])
            logging.info(f"Deleted signing certificate: {cert['CertificateId']}")

        # 🔥 Final kill
        iam.delete_user(UserName=user)
        logging.info(f"✅ User '{user}' deleted successfully.")

    except iam.exceptions.NoSuchEntityException:
        logging.warning(f"User '{user}' does not exist.")
    except botocore.exceptions.ClientError as e:
        logging.error(f"AWS ClientError: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error while deleting user '{user}'")

def main():
    user_name = 'practice-user'  # Change as needed
    iam_client = get_iam_client()
    delete_user_completely(iam_client, user_name)

if __name__ == '__main__':
    main()
```
**Usage:**
```bash
python delete_user.py
```

### Create Group

Automate the creation of an IAM Group.
```python
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_group(group_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_group(GroupName=group_name)
        logging.info(f'Group {group_name} created successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error creating group: {e}')

create_group('DeveloperAdmin')
```
**Usage:**
```bash
python create_group.py
```

### Delete Group

Automate the deletion of an IAM Group.
```python
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_group(group_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_group(GroupName=group_name)
        logging.info(f'Group {group_name} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting group: {e}')

delete_group('DeveloperAdmin')
```

### Create Policy

Automate the creation of an IAM Policy with a custom policy document.
```python
import boto3
import json

def create_policy(policy_name, policy_document):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f'Policy {policy_name} created successfully.')
        print(response)
    except Exception as e:
        print(f'Error creating policy: {e}')

policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}

create_policy('S3FullAccessPolicy', policy_document)
```
**Usage:**
```bash
python create_policy.py
```

### Delete Policy
Automate the deletion of an IAM Policy.
```python
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_policy(policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting policy: {e}')

delete_policy('arn:aws:iam::aws:policy/S3FullAccessPolicy')
```
**Usage:**
```bash
python delete_policy.py
```

### Attach User Policy
Automate attaching a policy to an IAM User.
```python
import boto3

def attach_user_policy(user_name, policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn
        )
        print(f'Policy {policy_arn} attached to user {user_name} successfully.')
        print(response)
    except Exception as e:
        print(f'Error attaching policy to user: {e}')

attach_user_policy('JohnDoe', 'arn:aws:iam::aws:policy/S3FullAccessPolicy')
```

**Usage:**
```bash
python delete_policy.py
```

### Detach User Policy
Automate detaching a policy from an IAM User.
```python
import boto3

def detach_user_policy(user_name, policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.detach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn
        )
        print(f'Policy {policy_arn} detached from user {user_name} successfully.')
        print(response)
    except Exception as e:
        print(f'Error detaching policy from user: {e}')

detach_user_policy('JohnDoe', 'arn:aws:iam::aws:policy/S3FullAccessPolicy')
```

**Usage:**
```bash
python detach_user_policy.py
```

### Create Role
Automate the creation of an IAM Role with a specified trust policy.
```python
import boto3
import json

def create_role(role_name, trust_policy):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        print(f'Role {role_name} created successfully.')
        print(response)
    except Exception as e:
        print(f'Error creating role: {e}')

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

create_role('EC2S3AccessRole', trust_policy)
```

**Usage:**
```bash
python create_role.py
```

### Delete Role
Automate the deletion of an IAM Role.
```python
import boto3

def delete_role(role_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_role(
            RoleName=role_name
        )
        print(f'Role {role_name} deleted successfully.')
        print(response)
    except Exception as e:
        print(f'Error deleting role: {e}')

delete_role('EC2S3AccessRole')
```

**Usage:**
```bash
python delete_role.py
```

### Attach Role Policy
Automate attaching a policy to an IAM Role.
```python
import boto3

def attach_role_policy(role_name, policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f'Policy {policy_arn} attached to role {role_name} successfully.')
        print(response)
    except Exception as e:
        print(f'Error attaching policy to role: {e}')

attach_role_policy('EC2S3AccessRole', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
```

**Usage:**
```bash
python attach_role_policy.py
```

### Detach Role Policy

Automate detaching a policy from an IAM Role.
```python
import boto3

def detach_role_policy(role_name, policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.detach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f'Policy {policy_arn} detached from role {role_name} successfully.')
        print(response)
    except Exception as e:
        print(f'Error detaching policy from role: {e}')

detach_role_policy('EC2S3AccessRole', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
```

**Usage:**
```bash
python detach_role_policy.py
```

## 🛠️ **Shell Script**

### `iam_automation.sh`
A shell script to run the Python automation scripts.
```
#!/bin/bash

# Run the Python script
python iam_automation.py
```
**Usage:**
```bash
chmod +x iam_automation.sh
./iam_automation.sh
```

### `iam_automation.py`
Combines role creation and deletion automation in one script.
```python
import boto3
import json

def create_iam_role(role_name, assume_role_policy):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        print(f'Role {role_name} created successfully.')
        print(response)
    except Exception as e:
        print(f'Error creating role: {e}')

def delete_iam_role(role_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_role(
            RoleName=role_name
        )
        print(f'Role {role_name} deleted successfully.')
        print(response)
    except Exception as e:
        print(f'Error deleting role: {e}')

# Example trust policy for EC2
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

if __name__ == '__main__':
    create_iam_role('EC2S3AccessRole', trust_policy)
    # Uncomment to delete the role
    # delete_iam_role('EC2S3AccessRole')
```

**Usage:**
```bash
python iam_automation.py
```

## 🔧 **Setup**

### Install Python Packages
Ensure you have the necessary Python packages installed.

```bash
pip install boto3
```

### Configure AWS Credentials

Set up your AWS credentials.

```bash
aws configure --profile newprofile
```

### Run Scripts

Execute the Python scripts directly or use the provided shell script to automate tasks.

## 📜 **Notes**

- Replace placeholder values (e.g., role names, policy ARNs) with your actual AWS resources.
- Ensure you have the necessary IAM permissions to execute these tasks.

## 📬 **Contact**

For any questions or contributions, feel free to connect via [LinkedIn](https://www.linkedin.com/in/maheshshukla01/) or create an issue in this repository.

