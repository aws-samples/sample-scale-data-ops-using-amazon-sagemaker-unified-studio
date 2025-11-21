"""
metadata_loader.py

This module provides utilities for loading and managing DataZone metadata JSON files.
It defines helper functions to deserialize various metadata models used in AWS DataZone
and related services, such as projects, user management, and account associations.

All loader functions validate file paths to prevent directory traversal,
handle JSON decoding and file errors gracefully, and log actions consistently.

Example:
    metadata = load_projects_metadata("projects_metadata.json")
    if metadata:
        project_names = get_project_names(metadata)
        print(project_names)
"""

import json
import os
import logging
from typing import List, Optional
from aws_cdk import Tags
from ..config.model import (
    DatazoneDomainMetadataModel,
    AccountAssociationMetadataModel,
    UserManagementMetadataModel,
    ProjectsMetadataModel,
    ProjectMetadataModel,
    ProjectMemberModel
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def load_json_file(metadata_path: str) -> Optional[DatazoneDomainMetadataModel]:
    """
    Load JSON metadata from a file and parse it into a DatazoneDomainMetadataModel.

    Args:
        metadata_path (str): Path to the JSON metadata file.

    Returns:
        Optional[DatazoneDomainMetadataModel]: Parsed metadata model if successful, else None.

    Raises:
        ValueError: If path traversal outside the current working directory is detected.
        Exception: For unexpected runtime or decoding errors.
    """
    try:
        abs_path = os.path.abspath(metadata_path)
        if not os.path.commonpath([abs_path, os.getcwd()]) == os.getcwd():
            raise ValueError("Path traversal detected")

        with open(abs_path, "r", encoding="utf-8") as file:
            config_data = json.load(file)
            logger.info("Metadata loaded successfully from %s", metadata_path)
            return DatazoneDomainMetadataModel(**config_data)

    except FileNotFoundError:
        logger.error("File not found: %s", metadata_path)
    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON from %s: %s", metadata_path, e)
    except Exception as ex:
        logger.error("Unexpected error loading JSON file %s: %s", metadata_path, ex)
    return None


def load_account_association(metadata_path: str = "metadata.json") -> Optional[List[AccountAssociationMetadataModel]]:
    """
    Load account association metadata list from a DataZone metadata file.

    Args:
        metadata_path (str): Optional path to the JSON metadata file.

    Returns:
        Optional[List[AccountAssociationMetadataModel]]: A list of account relationships if found, else None.
    """
    domain_metadata = load_json_file(metadata_path)
    if domain_metadata and getattr(domain_metadata, "account_association", None):
        return domain_metadata.account_association

    logger.warning("Account association data could not be loaded from %s", metadata_path)
    return None


def load_usermgmt_metadata(metadata_path: str) -> Optional[UserManagementMetadataModel]:
    """
    Load user management metadata from a JSON definition file.

    Args:
        metadata_path (str): File path of the user management metadata JSON.

    Returns:
        Optional[UserManagementMetadataModel]: Parsed user management model if loaded successfully, else None.

    Raises:
        ValueError: If the provided path attempts traversal outside the current working directory.
    """
    try:
        abs_path = os.path.abspath(metadata_path)
        if not os.path.commonpath([abs_path, os.getcwd()]) == os.getcwd():
            raise ValueError("Path traversal detected")

        with open(abs_path, "r", encoding="utf-8") as metadata_file:
            metadata = json.load(metadata_file)
            logger.info("User management metadata loaded successfully.")
            return UserManagementMetadataModel(**metadata)

    except FileNotFoundError:
        logger.error("File not found: %s", metadata_path)
    except json.JSONDecodeError as e:
        logger.error("JSON decoding error in %s: %s", metadata_path, e)
    except Exception as ex:
        logger.error("Unexpected error loading user management metadata from %s: %s", metadata_path, ex)
    return None


def load_projects_metadata(metadata_path: str = "projects_metadata.json") -> Optional[ProjectsMetadataModel]:
    """
    Load projects metadata from a JSON file containing DataZone project definitions.

    Args:
        metadata_path (str): Path to the JSON file containing project metadata.

    Returns:
        Optional[ProjectsMetadataModel]: The parsed projects metadata model if loaded successfully, else None.
    """
    try:
        abs_path = os.path.abspath(metadata_path)
        if not os.path.commonpath([abs_path, os.getcwd()]) == os.getcwd():
            raise ValueError("Path traversal detected")

        with open(abs_path, "r", encoding="utf-8") as file:
            config_data = json.load(file)
            logger.info("Projects metadata loaded successfully.")
            return ProjectsMetadataModel(**config_data)

    except FileNotFoundError:
        logger.error("File not found: %s", metadata_path)
    except json.JSONDecodeError as e:
        logger.error("JSON decoding error in %s: %s", metadata_path, e)
    except Exception as ex:
        logger.error("Unexpected error loading projects metadata from %s: %s", metadata_path, ex)
    return None


def get_project_names(metadata: ProjectsMetadataModel) -> List[str]:
    """
    Retrieve all project names from a ProjectsMetadataModel instance.

    Args:
        metadata (ProjectsMetadataModel): The metadata object containing project definitions.

    Returns:
        List[str]: A list of project names. Returns an empty list if no projects are defined.
    """
    if not metadata or not getattr(metadata, "projects", None):
        return []
    return [project.name for project in metadata.projects]


def get_project_by_name(metadata: ProjectsMetadataModel, project_name: str) -> Optional[ProjectMetadataModel]:
    """
    Find a project within metadata by its name.

    Args:
        metadata (ProjectsMetadataModel): The metadata that contains multiple projects.
        project_name (str): The exact name of the project to retrieve.

    Returns:
        Optional[ProjectMetadataModel]: The matching project object if found, else None.
    """
    for project in getattr(metadata, "projects", []):
        if project.name == project_name:
            return project
    logger.warning("Project named '%s' not found.", project_name)
    return None


def get_members_for_project(metadata: ProjectsMetadataModel, project_name: str) -> List[ProjectMemberModel]:
    """
    Retrieve all members associated with a specific project.

    Args:
        metadata (ProjectsMetadataModel): Metadata object that includes project definitions and members.
        project_name (str): The name of the project whose members need to be listed.

    Returns:
        List[ProjectMemberModel]: A list of members if the project is found; otherwise an empty list.
    """
    project = get_project_by_name(metadata, project_name)
    if project and getattr(project, "members", None):
        return project.members
    return []