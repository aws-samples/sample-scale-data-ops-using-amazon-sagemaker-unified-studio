#!/usr/bin/env python3

import argparse
import json
import logging
import sys
import time
import boto3
import botocore
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Use DataZone admin role created by the stack
sts_client = boto3.client('sts')

try:
    caller_identity = sts_client.get_caller_identity()
    account_id = caller_identity['Account']
    region = sts_client.meta.region_name
    
    # Use the domain execution role which has built-in domain permissions
    datazone_admin_role_arn = f"arn:aws:iam::{account_id}:role/cdk-hnb659fds-cfn-exec-role-{account_id}-{region}"
    
    assumed_role = sts_client.assume_role(
        RoleArn=datazone_admin_role_arn,
        RoleSessionName="datazone-admin"
    )
    credentials = assumed_role['Credentials']
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    logger.info(f"Successfully assumed DataZone admin role: {datazone_admin_role_arn}")
except Exception as e:
    logger.warning(f"Failed to assume DataZone admin role: {e}. Using default credentials.")
    session = boto3.Session()

DATAZONE_CLIENT = session.client("datazone", region_name=region)

logger.info(f"Running with boto3 version: {boto3.__version__}")
logger.info(f"Running with botocore version: {botocore.__version__}")


def fetch_user_id(domain_identifier: str, identifier: str) -> str:
    """
    Fetch the user ID for a given user identifier (email or IAM username) in the DataZone domain.

    Args:
        domain_identifier (str): The DataZone domain identifier.
        identifier (str): User identifier, could be email or IAM username.

    Returns:
        str or None: The user ID if found, else None.
    """
    user_type = "DATAZONE_SSO_USER" if "@" in identifier else "DATAZONE_IAM_USER"
    try:
        response = DATAZONE_CLIENT.search_user_profiles(
            domainIdentifier=domain_identifier,
            searchText=identifier,
            maxResults=1,
            userType=user_type
        )
        if response.get("items"):
            user_id = response["items"][0]["id"]
            logger.info(f"Found user id '{user_id}' for identifier '{identifier}'")
            return user_id
        else:
            logger.info(f"No user profile found for identifier '{identifier}'")
    except Exception as e:
        logger.error(f"Error fetching user id for '{identifier}': {e}")
    return None


def fetch_group_id(domain_identifier: str, group_name: str) -> str:
    """
    Fetch the group ID for a given group name in the DataZone domain.

    Args:
        domain_identifier (str): The DataZone domain identifier.
        group_name (str): The name of the group.

    Returns:
        str or None: The group ID if found, else None.
    """
    try:
        response = DATAZONE_CLIENT.search_group_profiles(
            domainIdentifier=domain_identifier,
            searchText=group_name,
            maxResults=1,
            groupType="DATAZONE_SSO_GROUP"
        )
        if response.get("items"):
            group_id = response["items"][0]["id"]
            logger.info(f"Found group id '{group_id}' for group name '{group_name}'")
            return group_id
        else:
            logger.info(f"No group profile found for group name '{group_name}'")
    except Exception as e:
        logger.error(f"Error fetching group id for '{group_name}': {e}")
    return None


def get_root_domain_unit_id(domain_identifier: str) -> str:
    """
    Retrieve the root domain unit ID for a given DataZone domain, retrying up to 5 times on failure.

    Args:
        domain_identifier (str): The DataZone domain identifier.

    Returns:
        str: The root domain unit ID.

    Raises:
        ValueError: If the root domain unit ID is not found after retries.
    """
    for attempt in range(1, 6):
        try:
            response = DATAZONE_CLIENT.get_domain(identifier=domain_identifier)
            root_domain_unit_id = response.get("rootDomainUnitId")
            if root_domain_unit_id:
                logger.info(f"Obtained root domain unit id: {root_domain_unit_id}")
                return root_domain_unit_id
            else:
                logger.warning("Root domain unit ID not found in response.")
        except Exception as e:
            logger.error(f"Attempt {attempt}: Error getting root domain unit ID: {e}")
            if attempt < 5:  # Don't sleep on last attempt
                time.sleep(min(2 ** attempt, 10))  # Exponential backoff
    raise ValueError("rootDomainUnitId not found after multiple retries.")


def add_root_domain_owners(metadata_path: str) -> None:
    """
    Add owners specified in the metadata JSON file as owners of the root domain unit.

    Args:
        metadata_path (str): Path to the JSON file containing domain metadata.

    Exits:
        Exits the script if the metadata file is missing or invalid,
        or if the domain ARN is missing.
    """
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except FileNotFoundError:
        logger.error(f"Metadata file not found: {metadata_path}")
        sys.exit(1)
    except json.JSONDecodeError as jde:
        logger.error(f"Failed to parse JSON: {jde}")
        sys.exit(1)

    domain_arn = metadata.get("domain_arn")
    if not domain_arn:
        logger.error("metadata is missing 'domain_arn'. Cannot proceed.")
        sys.exit(1)

    domain_identifier = domain_arn.split("/")[-1]
    logger.info(f"Using domain_identifier: {domain_identifier}")
    logger.info("Determining root domain unit ID...")
    root_domain_unit_id = get_root_domain_unit_id(domain_identifier)
    logger.info(f"Resolved rootDomainUnitId: {root_domain_unit_id}")

    root_domain_owners = metadata.get("root_domain_owners", [])
    if not root_domain_owners:
        logger.info("No 'root_domain_owners' specified in metadata. Nothing to add.")
        return

    for owner_entry in root_domain_owners:
        logger.info(f"Processing owner entry: {owner_entry}")

        if "groupname" in owner_entry:
            group_id = fetch_group_id(domain_identifier, owner_entry["groupname"])
            if not group_id:
                logger.error(f"Could not resolve group_id for groupname='{owner_entry['groupname']}'. Skipping.")
                continue
            owner_payload = {"group": {"groupIdentifier": group_id}}

        elif "username" in owner_entry:
            user_id = fetch_user_id(domain_identifier, owner_entry["username"])
            if not user_id:
                logger.error(f"Could not resolve user_id for username='{owner_entry['username']}'. Skipping.")
                continue
            owner_payload = {"user": {"userIdentifier": user_id}}

        elif "role_arn" in owner_entry:
            owner_payload = {"user": {"userIdentifier": owner_entry["role_arn"]}}

        else:
            logger.warning(f"Unrecognized owner type in entry: {owner_entry}. Skipping.")
            continue

        logger.info(f"Adding owner: {json.dumps(owner_payload)} to rootDomainUnitId='{root_domain_unit_id}'")
        logger.info(f"Domain identifier: {domain_identifier}, Root domain unit ID: {root_domain_unit_id}")
        if domain_identifier == root_domain_unit_id:
            logger.warning("Root domain unit ID is same as domain identifier - this may cause permission issues")
        
        try:
            resp = DATAZONE_CLIENT.add_entity_owner(
                domainIdentifier=domain_identifier,
                entityType="DOMAIN_UNIT",
                entityIdentifier=root_domain_unit_id,
                owner=owner_payload
            )
            logger.info(f"add_entity_owner response: {json.dumps(resp, default=str)}")
            logger.info("Successfully added owner to root domain unit.")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                logger.info(f"Access denied for adding owner. Check IAM permissions for DataZone:AddEntityOwner. Skipping owner: {owner_payload}")
            else:
                logger.error(f"Failed to add owner: {e}")
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add root domain owners to a Datazone domain.")
    parser.add_argument("--metadata-path", required=True, type=str, help="Path to the metadata JSON file.")
    args = parser.parse_args()
    add_root_domain_owners(args.metadata_path)
