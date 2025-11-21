import boto3
import logging
import argparse
import os
from datazone.config.utils import load_account_association

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
    Default to 'us-east-1' if none found.
    """
    region = os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION')
    if region:
        return region
    session = boto3.session.Session()
    return session.region_name or "us-east-1"

def create_resource_shares(metadata_path: str):
    """
    Create AWS RAM resource shares based on account association metadata.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON metadata file containing account associations.

    Raises
    ------
    ValueError
        If no account associations are defined in the metadata.
    """
    account_associations = load_account_association(metadata_path)
    logger.info(f'Loaded {len(account_associations) if account_associations else 0} account associations from {metadata_path}')
    if not account_associations:
        raise ValueError("No account associations defined in the metadata.")

    region = get_aws_region()
    ram_client = boto3.client("ram", region_name=region)

    for association in account_associations:
        account_id = association.target_account_id
        target_accounts = association.target_accounts or []
        if account_id:
            target_accounts = [account_id]

        resource_share_name = association.resource_share_name
        domain_arn = association.domain_arn
        permissions = association.permissions

        if not (resource_share_name and domain_arn and target_accounts and permissions):
            logger.warning(
                f"Skipping incomplete account association: "
                f"resource_share_name={resource_share_name}, domain_arn={domain_arn}, "
                f"target_accounts={target_accounts}, permissions={permissions}"
            )
            continue

        try:
            logger.info(f"Checking resource share '{resource_share_name}' existence...")
            response = ram_client.get_resource_shares(
                resourceOwner='SELF',
                name=resource_share_name
            )
            resource_shares = response.get("resourceShares", [])
            if resource_shares:
                resource_share_arn = resource_shares[0]["resourceShareArn"]
                logger.info(f"Resource share '{resource_share_name}' exists (ARN: {resource_share_arn}), deleting it...")
                ram_client.delete_resource_share(resourceShareArn=resource_share_arn)
                logger.info(f"Deleted existing resource share '{resource_share_name}'.")
            else:
                logger.info(f"No existing resource share found for '{resource_share_name}'. Will create a new one.")
        except Exception as e:
            logger.error(f"Error retrieving or deleting resource share '{resource_share_name}': {e}")
            continue

        try:
            logger.info(f"Creating resource share '{resource_share_name}' for principals {target_accounts} with permissions '{permissions}'")
            response = ram_client.create_resource_share(
                name=resource_share_name,
                resourceArns=[domain_arn],
                principals=target_accounts,
                permissionArns=[permissions]
            )
            created_arn = response["resourceShare"]["resourceShareArn"]
            logger.info(f"Successfully created resource share '{resource_share_name}' with ARN: {created_arn}")
        except Exception as e:
            logger.error(f"Failed to create resource share '{resource_share_name}': {e}")

def remove_resource_shares(metadata_path: str):
    """
    Remove AWS RAM resource shares based on account association metadata.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON metadata file containing account associations.

    Raises
    ------
    ValueError
        If no account associations are defined in the metadata.
    """
    account_associations = load_account_association(metadata_path)
    logger.info(f'Loaded {len(account_associations) if account_associations else 0} account associations from {metadata_path}')
    if not account_associations:
        raise ValueError("No account associations defined in the metadata.")

    region = get_aws_region()
    ram_client = boto3.client("ram", region_name=region)

    for association in account_associations:
        account_id = association.target_account_id
        target_accounts = association.target_accounts or []
        if account_id:
            target_accounts = [account_id]

        resource_share_name = association.resource_share_name
        domain_arn = association.domain_arn
        permissions = association.permissions

        if not (resource_share_name and domain_arn and target_accounts and permissions):
            logger.warning(f"Skipping incomplete account association: {association}")
            continue

        try:
            logger.info(f"Checking if resource share '{resource_share_name}' exists...")
            response = ram_client.get_resource_shares(
                resourceOwner='SELF',
                name=resource_share_name
            )
            resource_shares = response.get("resourceShares", [])
            if resource_shares:
                logger.info(f"Resource share '{resource_share_name}' exists, proceeding to delete.")
                resource_share_arn = resource_shares[0]["resourceShareArn"]
                ram_client.delete_resource_share(resourceShareArn=resource_share_arn)
                logger.info(f"Successfully deleted resource share '{resource_share_name}'.")
            else:
                logger.info(f"No resource share '{resource_share_name}' found. Skipping deletion.")
        except Exception as e:
            logger.error(f"Failed to check or delete resource share '{resource_share_name}': {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage AWS RAM resource shares for account associations.")
    parser.add_argument("--metadata-path", required=True, help="Path to the metadata JSON file.")
    parser.add_argument("--action", required=True, choices=["add", "remove"], help="Action to perform: add or remove.")

    args = parser.parse_args()

    if args.action == "add":
        logger.info(f"Starting to add resource shares using metadata from: {args.metadata_path}")
        create_resource_shares(args.metadata_path)
    elif args.action == "remove":
        logger.info(f"Starting to remove resource shares using metadata from: {args.metadata_path}")
        remove_resource_shares(args.metadata_path)