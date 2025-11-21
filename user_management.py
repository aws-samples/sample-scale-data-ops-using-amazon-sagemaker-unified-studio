import boto3
import logging
import argparse
import os
from datazone.config.utils import load_usermgmt_metadata
from datazone.config.model import UserManagementMetadataModel

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
logger = logging.getLogger(__name__)

# Enable detailed boto3 and botocore logging at WARNING level (to avoid noisy info/debug logs)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)

def get_aws_region():
    """
    Determine AWS region from environment variables or boto3 session default.
    Defaults to 'us-east-1' if none found.
    """
    region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION')
    if region:
        return region
    session = boto3.session.Session()
    return session.region_name or "us-east-1"

def manage_user_profiles(metadata_path: str):
    """
    Manage user profiles in Amazon DataZone from user management metadata.

    For each SSO user, IAM role, and SSO group from the metadata:
    - Checks if the user/group/role profile exists.
    - Creates the profile if it does not exist.
    - Updates the profile status if needed.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON user management metadata file.
    """
    try:
        metadata: UserManagementMetadataModel = load_usermgmt_metadata(metadata_path)
        logger.info(f"User management metadata loaded successfully: domain ARN type={type(metadata.domain_arn)}")
        logger.info(f"User management domain ARN: {metadata.domain_arn}")
    except Exception as e:
        logger.error(f"Failed to load metadata from {metadata_path}: {e}")
        return

    domain_arn = metadata.domain_arn
    domain_identifier = domain_arn.split("/")[-1]
    logger.info(f"Domain identifier extracted: {domain_identifier}")

    sso_users = metadata.sso_users or []
    iam_roles = metadata.iam_roles or []
    sso_groups = metadata.sso_groups or []

    region = get_aws_region()
    client = boto3.client("datazone", region_name=region)
    logger.info(f"Using AWS region: {region} for DataZone client")

    def process_user(user_name: str, user_type: str):
        try:
            current_arn = boto3.client('sts').get_caller_identity()['Arn']
            logger.debug(f"Caller ARN: {current_arn}")
            logger.debug(f"Processing user '{user_name}' with type '{user_type}' in domain '{domain_identifier}'")

            response = client.get_user_profile(domainIdentifier=domain_identifier, userIdentifier=user_name)
            current_status = response.get("status")
            logger.info(f"User profile '{user_name}' found with status: {current_status}")

            if current_status == "DEACTIVATED":
                logger.info(f"Reactivating user profile '{user_name}'")
                client.update_user_profile(
                    domainIdentifier=domain_identifier,
                    status="ACTIVATED",
                    type="SSO" if user_type == "SSO_USER" else "IAM",
                    userIdentifier=user_name,
                )
            elif current_status == "NOT_ASSIGNED":
                logger.info(f"Assigning user profile '{user_name}'")
                client.update_user_profile(
                    domainIdentifier=domain_identifier,
                    status="ASSIGNED",
                    type="SSO" if user_type == "SSO_USER" else "IAM",
                    userIdentifier=user_name,
                )
            else:
                logger.info(f"No update required for user '{user_name}' with status '{current_status}'")

        except client.exceptions.ResourceNotFoundException:
            logger.info(f"User profile '{user_name}' not found, creating new profile")
            try:
                client.create_user_profile(
                    domainIdentifier=domain_identifier,
                    userIdentifier=user_name,
                    userType=user_type
                )
                logger.info(f"Created user profile for '{user_name}'")
            except Exception as e:
                logger.error(f"Failed to create user profile for '{user_name}': {e}")
        except Exception as e:
            logger.error(f"Error managing user profile '{user_name}': {e}")

    # Process SSO users
    for user in sso_users:
        process_user(user.username, "SSO_USER")

    # Process IAM roles
    for role in iam_roles:
        process_user(role.role_arn, "IAM_ROLE")

    # Process SSO groups
    for group in sso_groups:
        group_name = group.groupname
        try:
            response = client.get_group_profile(domainIdentifier=domain_identifier, groupIdentifier=group_name)
            logger.info(f"Group profile '{group_name}' exists")
            current_status = response.get("status")
            if current_status == "NOT_ASSIGNED":
                client.update_group_profile(
                    domainIdentifier=domain_identifier,
                    groupIdentifier=group_name,
                    status='ASSIGNED'
                )
                logger.info(f"SSO group profile reactivated: {group_name}")
            else:
                logger.info(f"SSO group profile already assigned: {group_name}")
        except client.exceptions.ResourceNotFoundException:
            logger.info(f"Creating new SSO group profile: {group_name}")
            try:
                client.create_group_profile(
                    domainIdentifier=domain_identifier,
                    groupIdentifier=group_name
                )
                logger.info(f"SSO group profile created: '{group_name}'")
            except Exception as e:
                logger.error(f"Failed to create SSO group profile '{group_name}': {e}")
        except Exception as e:
            logger.error(f"Error managing group profile '{group_name}': {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage Amazon DataZone user profiles from metadata JSON.")
    parser.add_argument("--metadata-path", required=True, type=str, help="Path to the metadata JSON file.")
    args = parser.parse_args()

    logger.info(f"Starting manage_user_profiles with metadata path: {args.metadata_path}")
    manage_user_profiles(args.metadata_path)