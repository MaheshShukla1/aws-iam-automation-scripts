import boto3
import json
import logging
from datetime import datetime,timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Iam client
iam_client = boto3.client('iam')

# Helper function to log the response log_response function
def log_response(action,response):
    logging.info(f'{action} response: {json.dumps(response,indent=4,default=str)}')

    # Purpose: This function logs the response from AWS IAM actions in a formatted way for easier reading and debugging.

    # Parameters
    # action: A string describing the IAM action performed (e.g., "Create User").
    # response: The response object returned by the IAM action.

    # Functionality:
    # Uses the json.dumps function to convert the response object to a JSON string with indentation.
    # Logs the formatted response using logging.info.

# Create User with MFA create_user_with_mfa function

def create_user_with_mfa(user_name,password,mfa_code_1,mfa_code_2):
    try:
        # Create User
        response = iam_client.create_user(UserName=user_name)
        logging.info(f'User {user_name} created successfully.')
        logging.info(response)

        # Purpose: Creates an IAM user and sets up MFA (Multi-Factor Authentication) for them.
        # Parameters:
        # user_name: The name of the IAM user to create.
        # password: The password for the user's login profile.
        # mfa_code1: The first MFA code for enabling the virtual MFA device.
        # mfa_code2: The second MFA code for enabling the virtual MFA device.

        # Functionality:
        # Create User:
        # Calls iam_client.create_user to create a new IAM user.
        # Logs the successful creation of the user.
        # Calls log_response to log the detailed response from AWS.
       
        # Create login profile with password
        response = iam_client.create_login_profile(UserName=user_name,Password=password,PasswordResetRequired=True)
        logging.info(f'Login profile for {user_name} created successfully.')
        log_response('Create login profile',response)

        # Create Login Profile:
        # Calls iam_client.create_login_profile to create a login profile with a specified password for the user.
        # Sets PasswordResetRequired to True, forcing the user to reset their password upon first login.
        # Logs the successful creation of the login profile and the detailed response.

        # Create Virtual MFA Device
        mfa_response = iam_client.create_virtual_mfa_device(VirtualMFADeviceName=f'{user_name}_mfa')
        logging.info(f'Virtual mfa device created for {user_name}')
        log_response('Create virtual mfa device',mfa_response)

        # Create Virtual MFA Device:
        # Calls iam_client.create_virtual_mfa_device to create a virtual MFA device for the user.
        # Names the MFA device based on the user's name for easy identification.
        # Logs the successful creation of the virtual MFA device and the detailed response.

        # Enable MFA For user
        iam_client.enable_mfa_device(
            UserName=user_name,
            SerialNumber=mfa_response['VirtualMFADevice']['SerialNumber'],
            AuthenticationCode1=mfa_code_1,
            AuthenticationCode2=mfa_code_2
        )
        logging.info(f'MFA Enabled for {user_name}')

        # Enable MFA:
        # Calls iam_client.enable_mfa_device to enable MFA for the user.
        # Uses the serial number from the virtual MFA device response and the two MFA codes provided.
        # Logs the successful enabling of MFA.
        # Error Handling:
        # Catches any exceptions that occur during the process and logs an error message.
    except Exception as e:
        logging.error(f'Error creating user or setting up MFA: {e}')

# Rotate Access Key
def rotate_access_key(user_name):
    try:
        # Create a new access key
        new_key_response = iam_client.create_access(UserName=user_name)
        logging.info(f'New Access key created for {user_name}')
        log_response('Create access keys',new_key_response)

        # Purpose: Rotates the access keys for an IAM user by creating a new key and deactivating/deleting old ones.
        # Parameters:
        # user_name: The name of the IAM user for whom the access key rotation will be performed.

        # Functionality:
        # Create New Access Key:
        # Calls iam_client.create_access_key to create a new access key for the user.
        # Logs the successful creation of the new access key and the detailed response.

        # Deactivate old access keys (if any)
        list_keys_response = iam_client.list_access_keys(UserName=user_name)
        for key in list_keys_response['AccessKeyMetadata']:
            if key['AccessKeyId'] != new_key_response['AccessKey']['AccessKeyId']:
                iam_client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
                logging.info(f'Access key {key["AccessKeyId"]} deactivated for {user_name}.')
                # List and Deactivate Old Access Keys:
                # Calls iam_client.list_access_keys to list all access keys for the user.
                # Iterates through each key in the list.
                # If the key ID is not the same as the newly created access key, it deactivates the old key by setting its status to 'Inactive'.
                # Logs the deactivation of each old access key.

                # Delete old access keys
                for key in list_keys_response['AccessKeyMetaData']:
                    if key['AccessKeyId'] != new_key_response['AccessKey']['AccessKeyId']:
                        iam_client.delete_access_key(
                            UserName=user_name,
                            AccessKeyId=key['AccessKeyId']
                        )
                        logging.info(f'Access key {key["AccessKeyId"]} deleted for {user_name}.')            
        # Delete Old Access Keys:
        # Iterates through the list of access keys again.
        # If the key ID is not the same as the newly created access key, it deletes the old key.
        # Logs the deletion of each old access key.
        
        # Error Handling:
        # Catches any exceptions that occur during the process and logs an error message.
    except Exception as e:
        logging.error(f'Error rotating access key: {e}')              

        




    


