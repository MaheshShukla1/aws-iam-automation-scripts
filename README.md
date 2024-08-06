# AWS IAM Automation Scripts

This repository contains scripts for automating AWS Identity and Access Management (IAM) tasks using Python with Boto3 and AWS CLI. The automation includes creating and managing IAM policies, roles, and their attachments.

## 📂 **Contents**

1. **Python Scripts**
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
   - [Atach Role Policy](#attach-role-policy)
   - [Detach Role Policy](#detach-role-policy)
   
3. **Shell Script**
   - `iam_automation.sh`

## 📜 **Python Scripts**
### Create User
Creates an IAM User.

```python
def create_user(user_name):
    try:
        response = iam_client.create_user(UserName=user_name)
        print(f'User {user_name} created successfully.')
        print(response)
    except Exception as e:
        print(f'Error creating user: {e}')

create_user('Alice')
```
**Usage:**
```python
python create_user.py
```
### Delete User
Delete an IAM User.

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
```python
python delete_user.py
```

### Create Group
Creates an IAM Group.

```python
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
def create_group(group_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_group(GroupName=group_name)
        logging.info(f'Group {group_name} created succesfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error creating group: {e}')

create_group('DeveloperAdmin')
```
**Usage:**
```python
python create_group.py
```
### Delete Group
Delete an IAM Group.

```python
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
def delete_group(group_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_group(GroupName=group_name)
        logging.info(f'Deleting Group {group_name} deleted successfully.')
        logging.info(response)
    except Exception as e:
        logging.error(f'Error deleting group: {e}')

delete_group('DeveloperAdmin')
```
**Usage:**
```python
python delete_group.py
```

### Create Policy
Creates an IAM policy.

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
## Delete Policy
Delete an IAM Policy

```python
def delete_policy(policy_arn):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
        logging.info(response)
    except Exception as e:
        print(f'Error deleting policy: {e}')
```

***Usage***
```bash
python delete_policy.py
```

### Attach User Policy
Attaches a policy to user.

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
python attach_user_policy.py
```

### Detach User Policy
Detaches a policy from user.

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

**Usage**
```bash
python detach_user_policy.py
```

### Create Role
Creates an IAM Role with a trust policy.

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
**Usage**
```bash
python create_role.py
```
### Delete Role 
Delets an IAM Role.

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
**Usage**
```bash
python delete_role.py
```

### Atach Role Policy
Attaches a Role policy to a role.

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
**Usage**
```bash
python attach_role_policy.py
```

### Detach Role Policy
Detaches a Role policy from a role.

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
**Usage**
```bash
python detach_role_policy.py
```

## 🛠️ Shell Script

### `iam_automation.sh`
Shell script to run the Python automation script.

**Usage**
```bash
chmod +x iam_automation.sh
./iam_automation.sh
```
Example Code:
```bash
#!/bin/bash

# Run the Python script
python iam_automation.py
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
**Usage**
```bash
python iam_automation.py
```
## `🔧 Setup`
#### `Install Python Packages`
```bash
pip install boto3
```
#### `Configure AWS Credentials`
```bash
aws configure --profile newprofile
```

#### `Run Scripts`
For Python scripts: Execute directly or use the shell script to automate tasks.

## `📜 Notes`
Replace placeholder values (e.g., role names, policy ARNs) with your actual AWS resources.
Ensure you have the necessary IAM permissions to execute these tasks.

## `📬 Contact`
For any questions or contributions, please reach out via [Linkedin](https://www.linkedin.com/in/maheshshukla01/) or create an issue in this repository.
