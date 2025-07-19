d# 🚀 AWS IAM Automation Scripts

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
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def delete_user(user_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_user(UserName=user_name)
        logging.info(f'User {user_name} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting user: {e}')

delete_user('Alice')
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

