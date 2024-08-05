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


    


