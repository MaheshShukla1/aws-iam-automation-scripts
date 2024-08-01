import boto3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

iam_client = boto3.client('iam')

def delete_policy(policy_arn):
    try:
         # entity: This variable holds the current entity type from the loop, Which can be 'users', 'group' or 'roles'
        for entity in ['User', 'Group', 'Role']:
            response = iam_client.list_entities_for_policy(
                PolicyArn=policy_arn,
                EntityFilter=entity
            )
             # entity[:-1]: This expression removes the last character from the entity string. So, for 'users' it becomes 'user', for 'groups' it becomes 'group', and for 'roles' it becomes 'role'.

            # f'detach_{entity[:-1]}_policy': This constructs a string for the method name. For example, if entity is 'users', the resulting string is 'detach_user_policy'.

            # getattr(iam_client, ...): The getattr function retrieves the method from the iam_client object based on the constructed string. For 'users', it retrieves iam_client.detach_user_policy.
            for item in response.get(f'{entity}s', []):
                detach_method = getattr(iam_client, f'detach_{entity.lower()}_policy')

                # Constructing the parameters
                detach_method(
                    **{f'{entity}Name': item['UserName'] if entity == 'User' else item['GroupName'] if entity == 'Group' else item['RoleName']},
                    PolicyArn=policy_arn
                )
        
        iam_client.delete_policy(PolicyArn=policy_arn)
        logging.info(f'Policy {policy_arn} deleted successfully.')
    except Exception as e:
        logging.error(f'Error deleting policy: {e}')

delete_policy('arn:aws:iam::851725195108:policy/AccessPolicy')
