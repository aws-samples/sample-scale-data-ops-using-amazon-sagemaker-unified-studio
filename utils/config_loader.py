import json
import os
import logging
import re
from functools import lru_cache
import boto3

logger = logging.getLogger(__name__)


class ConfigLoader:
    """
    A utility class for loading and parsing configuration files, schema definitions,
    and resolving environment identifiers. Includes JSON loading with error handling,
    regex-based parsing of schema definitions, and environment resolution via boto3.
    """

    @staticmethod
    def load(file_path: str):
        """
        Load JSON data from a file with exception handling.

        Parameters
        ----------
        file_path : str
            Path to the JSON file.

        Returns
        -------
        dict or None
            Parsed JSON data from the file, or None if an error occurs.
        """
        try:
            # Prevent path traversal: ensure file_path is inside current working directory
            abs_path = os.path.abspath(file_path)
            cwd = os.getcwd()
            if not abs_path.startswith(cwd):
                raise ValueError("Path traversal detected")

            with open(abs_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.info("Successfully loaded JSON data from %s", file_path)
            return config

        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
        except json.JSONDecodeError as e:
            logger.error("JSON decode error in file %s: %s", file_path, e)
        except ValueError as ve:
            logger.error("Invalid file path: %s", ve)
        except Exception as e:
            logger.error("Unexpected error loading file %s: %s", file_path, e)
        return None

    @staticmethod
    def parse_schema_definition(text: str):
        """
        Parse schema definition text to extract fields, form name, and type identifier.

        Parameters
        ----------
        text : str
            The schema definition string to parse.

        Returns
        -------
        tuple
            A tuple of (fields: dict, form_name: str or None, type_identifier: str or None).
        """
        fields = {}
        form_name = None
        type_identifier = None

        # Pattern to match form name and type identifier
        form_pattern = r'@amazon\.datazone#displayname\(defaultName:\s*"([^"]*)"\)\s*structure\s+(\w+)'
        form_match = re.search(form_pattern, text)
        if form_match:
            form_name = form_match.group(1)
            type_identifier = form_match.group(2)

        # Pattern to match field names with type String
        field_name_pattern = r'(\w+):\s*String'

        # Find all field definitions
        for match in re.finditer(field_name_pattern, text):
            field_name = match.group(1)
            fields[field_name] = ""

        return fields, form_name, type_identifier

    @staticmethod
    def parse_input_texts(input_texts):
        """
        Parse a list of schema definition texts and prepare form input dictionaries
        with additional metadata values.

        Parameters
        ----------
        input_texts : list of str
            List of schema definition strings.

        Returns
        -------
        list of dict
            List of form input dictionaries with keys: 'content', 'formName', 'typeIdentifier'.
        """
        forms_input = []

        for text in input_texts:
            fields, form_name, type_identifier = ConfigLoader.parse_schema_definition(text)

            form_input = {
                'content': json.dumps(fields),
                'formName': form_name,
                'typeIdentifier': type_identifier
            }

            forms_input.append(form_input)

        values = {
            "tags": "catalog",
            "dataClassification": "Internal",
            "owner": "Data Team",
            "description": "Catalog data product"
        }

        for form in forms_input:
            existing_content = json.loads(form['content'])
            existing_content.update(values)
            form['content'] = json.dumps(existing_content)

        return forms_input

    ENV_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,36}$')

    @staticmethod
    def resolve_environment_id(domain_identifier: str, env_name_or_id: str) -> str:
        """
        Resolve an environment name or ID to an environment ID within a domain.

        Parameters
        ----------
        domain_identifier : str
            The domain identifier where the environment is located.
        env_name_or_id : str
            Environment name or ID to resolve.

        Returns
        -------
        str
            The resolved environment ID.

        Raises
        ------
        ValueError
            If the environment could not be found.
        """
        if ConfigLoader.ENV_ID_PATTERN.fullmatch(env_name_or_id):
            return env_name_or_id

        client = boto3.client("datazone")
        resp = client.list_environments(domainIdentifier=domain_identifier)
        for env in resp.get("items", []):
            if env.get("name") == env_name_or_id:
                return env.get("id")
        raise ValueError(f"Environment not found: {env_name_or_id}")