"""Utility functions for converting between different data representations."""

from typing import Any, Dict, List, Optional


class Converters:
    """Utility class containing conversion functions."""

    @staticmethod
    def entity_to_dict(entity: Any) -> Dict[str, Any]:
        """Convert an entity object to a dictionary.
        
        Args:
            entity: The entity to convert
            
        Returns:
            Dictionary representation of the entity
        """
        if hasattr(entity, '__dict__'):
            return {
                key: value for key, value in entity.__dict__.items()
                if not key.startswith('_')
            }
        return {}

    @staticmethod
    def dict_to_entity(data: Dict[str, Any], entity_class: type) -> Any:
        """Convert a dictionary to an entity object.
        
        Args:
            data: Dictionary containing entity data
            entity_class: The entity class to instantiate
            
        Returns:
            Instance of the entity class
        """
        return entity_class(**data)

    @staticmethod
    def filter_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove None values from a dictionary.
        
        Args:
            data: Dictionary to filter
            
        Returns:
            Dictionary with None values removed
        """
        return {key: value for key, value in data.items() if value is not None}

    @staticmethod
    def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Safely get a value from a dictionary.
        
        Args:
            data: Dictionary to get value from
            key: Key to look up
            default: Default value if key not found
            
        Returns:
            Value from dictionary or default
        """
        return data.get(key, default)

    @staticmethod
    def normalize_string(value: Optional[str]) -> Optional[str]:
        """Normalize a string value (trim whitespace, handle empty strings).
        
        Args:
            value: String value to normalize
            
        Returns:
            Normalized string or None
        """
        if value is None:
            return None
        
        normalized = value.strip()
        return normalized if normalized else None

    @staticmethod
    def convert_to_string_list(values: List[Any]) -> List[str]:
        """Convert a list of values to strings.
        
        Args:
            values: List of values to convert
            
        Returns:
            List of string representations
        """
        return [str(value) for value in values if value is not None]

    @staticmethod
    def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple dictionaries, with later dicts taking precedence.
        
        Args:
            *dicts: Variable number of dictionaries to merge
            
        Returns:
            Merged dictionary
        """
        result = {}
        for d in dicts:
            result.update(d)
        return result