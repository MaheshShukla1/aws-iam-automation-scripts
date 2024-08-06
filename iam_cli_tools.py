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


