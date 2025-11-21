import boto3
import logging
import argparse
import os
from datazone.config.utils import load_usermgmt_metadata
from datazone.config.model import UserManagementMetadataModel

# Configure root logger with ISO8601 timestamp format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
logger = logging.getLogger(__name__)
# Reduce boto3 and botocore log verbosity
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)

def get_aws_region():
    """
    Determine AWS region from environment variables or boto3 session config.
    Default to 'us-east-1' if unset.
    """
    region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION')
    if region:
        return region
    session = boto3.session.Session()
    return session.region_name or "us-east-1"

def remove_user_profiles(metadata_path: str):
    """
    Deactivate or unassign user profiles (SSO users, IAM roles, and SSO groups)
    in Amazon DataZone based on user management metadata JSON file.

    Parameters
    ----------
    metadata_path : str
        Path to user management metadata JSON file.
    """
    try:
        metadata: UserManagementMetadataModel = load_usermgmt_metadata(metadata_path)
        logger.info("User management metadata loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load metadata from {metadata_path}: {e}")
        return

    domain_identifier = metadata.domain_arn.split("/")[-1]
    sso_users = metadata.sso_users or []
    iam_roles = metadata.iam_roles or []
    sso_groups = metadata.sso_groups or []

    region = get_aws_region()
    client = boto3.client("datazone", region_name=region)
    logger.info(f"Using AWS region: {region} for DataZone client")

    def update_profile(user_identifier: str, user_type: str):
        try:
            response = client.get_user_profile(domainIdentifier=domain_identifier, userIdentifier=user_identifier)
            current_status = response.get("status")
            logger.info(f"Profile '{user_identifier}' ({user_type}) current status: {current_status}")
            if current_status == "ACTIVATED":
                logger.info(f"Deactivating profile '{user_identifier}'")
                client.update_user_profile(
                    domainIdentifier=domain_identifier,
                    status="DEACTIVATED",
                    type=user_type,
                    userIdentifier=user_identifier,
                )
            elif current_status == "ASSIGNED":
                logger.info(f"Unassigning profile '{user_identifier}'")
                client.update_user_profile(
                    domainIdentifier=domain_identifier,
                    status="NOT_ASSIGNED",
                    type=user_type,
                    userIdentifier=user_identifier,
                )
            else:
                logger.info(f"No update required for profile '{user_identifier}' with status '{current_status}'")
        except client.exceptions.ResourceNotFoundException:
            logger.warning(f"Profile '{user_identifier}' not found. Skipping.")
        except Exception as e:
            logger.error(f"Error processing profile '{user_identifier}': {e}")

    # Process SSO users
    for user in sso_users:
        update_profile(user.username, "SSO")

    # Process IAM roles
    for role in iam_roles:
        update_profile(role.role_arn, "IAM")

    # Process SSO groups
    for group in sso_groups:
        try:
            response = client.get_group_profile(domainIdentifier=domain_identifier, groupIdentifier=group.groupname)
            current_status = response.get("status")
            logger.info(f"Group profile '{group.groupname}' current status: {current_status}")
            if current_status == "ASSIGNED":
                logger.info(f"Unassigning group profile '{group.groupname}'")
                client.update_group_profile(
                    domainIdentifier=domain_identifier,
                    groupIdentifier=group.groupname,
                    status="NOT_ASSIGNED"
                )
            else:
                logger.info(f"No update required for group profile '{group.groupname}' with status '{current_status}'")
        except client.exceptions.ResourceNotFoundException:
            logger.warning(f"Group profile '{group.groupname}' not found. Skipping.")
        except Exception as e:
            logger.error(f"Error managing group profile '{group.groupname}': {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove user profiles from Amazon DataZone based on metadata JSON.")
    parser.add_argument("--metadata-path", required=True, type=str, help="Path to the metadata JSON file.")
    args = parser.parse_args()

    logger.info(f"Starting remove_user_profiles with metadata path: {args.metadata_path}")
    remove_user_profiles(args.metadata_path)
