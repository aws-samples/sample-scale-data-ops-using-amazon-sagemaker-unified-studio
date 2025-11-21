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
    Load JSON metadata from a file and parse it into DatazoneDomainMetadataModel.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON metadata file.

    Returns
    -------
    Optional[DatazoneDomainMetadataModel]
        Parsed data as a DatazoneDomainMetadataModel if file is found and valid,
        otherwise None.
    """
    try:
        if not os.path.abspath(metadata_path).startswith(os.getcwd()):
            raise ValueError("Path traversal detected")
        with open(metadata_path, 'r' encoding='utf-8') as file:
            config_data = json.load(file)
            logger.info("Metadata loaded successfully from %s", metadata_path)
            return DatazoneDomainMetadataModel(**config_data)
    except FileNotFoundError:
        logger.error("File not found: %s", metadata_path)
    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON from %s: %s", metadata_path, e)
    except Exception as ex:
        logger.error("Unexpected error loading json file %s: %s", metadata_path, ex)
    return None


def load_account_association(metadata_path: str = 'metadata.json') -> Optional[List[AccountAssociationMetadataModel]]:
    """
    Load account association metadata from file.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON metadata file.

    Returns
    -------
    Optional[List[AccountAssociationMetadataModel]]
        List of AccountAssociationMetadataModel if successful, else None.
    """
    domain_metadata = load_json_file(metadata_path)
    if domain_metadata:
        return domain_metadata.account_association
    else:
        logger.warning("Account association data could not be loaded from %s", metadata_path)
        return None


def load_usermgmt_metadata(metadata_path: str) -> Optional[UserManagementMetadataModel]:
    """
    Load user management metadata from JSON file.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON file.

    Returns
    -------
    Optional[UserManagementMetadataModel]
        Parsed UserManagementMetadataModel if successful, else None.
    """
    try:
        if not os.path.abspath(metadata_path).startswith(os.getcwd()):
            raise ValueError("Path traversal detected")
        with open(metadata_path, "r", encoding='utf-8') as metadata_file:
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


def load_projects_metadata(metadata_path: str = 'projects_metadata.json') -> Optional[ProjectsMetadataModel]:
    """
    Load projects metadata from a JSON file.

    Parameters
    ----------
    metadata_path : str
        Path to the JSON file.

    Returns
    -------
    Optional[ProjectsMetadataModel]
        Parsed ProjectsMetadataModel if successful, else None.
    """
    try:
        if not os.path.abspath(metadata_path).startswith(os.getcwd()):
            raise ValueError("Path traversal detected")
        with open(metadata_path, "r", encoding='utf-8') as file:
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
    Extract a list of project names from the projects metadata.

    Parameters
    ----------
    metadata : ProjectsMetadataModel
        The projects metadata object.

    Returns
    -------
    List[str]
        List containing the names of all projects.
    """
    return [project.name for project in metadata.projects]


def get_project_by_name(metadata: ProjectsMetadataModel, project_name: str) -> Optional[ProjectMetadataModel]:
    """
    Find and return a project by its name.

    Parameters
    ----------
    metadata : ProjectsMetadataModel
        The projects metadata to search.
    project_name : str
        The name of the project to find.

    Returns
    -------
    Optional[ProjectMetadataModel]
        The project if found, else None.
    """
    for project in metadata.projects:
        if project.name == project_name:
            return project
    logger.warning("Project named '%s' not found.", project_name)
    return None


def get_members_for_project(metadata: ProjectsMetadataModel, project_name: str) -> List[ProjectMemberModel]:
    """
    Retrieve members for a given project name.

    Parameters
    ----------
    metadata : ProjectsMetadataModel
        The projects metadata containing all projects.
    project_name : str
        The name of the project to get members for.

    Returns
    -------
    List[ProjectMemberModel]
        A list of members if project found, else an empty list.
    """
    project = get_project_by_name(metadata, project_name)
    if project and project.members:
        return project.members
    return []
