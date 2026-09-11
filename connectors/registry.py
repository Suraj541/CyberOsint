"""
Connector Registry
Provides dynamic registration and factory lookup for connector implementations.
"""

from typing import Dict, List, Optional, Type
from connectors.base import BaseConnector


class ConnectorRegistry:
    """Registry maintaining mappings between source_type/access_method and BaseConnector subclasses."""

    def __init__(self):
        self._registry: Dict[str, Type[BaseConnector]] = {}

    def register(self, source_type: str, connector_cls: Optional[Type[BaseConnector]] = None):
        """Register a new connector implementation class for a given source type."""
        key = source_type.lower().strip()
        if connector_cls is not None:
            if not issubclass(connector_cls, BaseConnector):
                raise TypeError(f"Connector class {connector_cls} must inherit from BaseConnector")
            self._registry[key] = connector_cls
            return connector_cls

        def decorator(cls_: Type[BaseConnector]) -> Type[BaseConnector]:
            if not issubclass(cls_, BaseConnector):
                raise TypeError(f"Connector class {cls_} must inherit from BaseConnector")
            self._registry[key] = cls_
            return cls_

        return decorator

    def unregister(self, source_type: str) -> bool:
        """Remove a connector implementation class for a given source type."""
        key = source_type.lower().strip()
        if key in self._registry:
            del self._registry[key]
            return True
        return False

    def get(self, source_type: str) -> Optional[Type[BaseConnector]]:
        """Retrieve the connector class for a source type, or None if not registered."""
        key = source_type.lower().strip()
        return self._registry.get(key)

    def create(self, source_type: str, source_config: Optional[dict] = None) -> BaseConnector:
        """Factory method to instantiate a connector for a given source type."""
        cls_ = self.get(source_type)
        if cls_ is None:
            raise KeyError(f"No connector registered for source type '{source_type}'")
        return cls_(source_config=source_config)

    def list_registered_types(self) -> List[str]:
        """Return a list of all registered source types."""
        return sorted(list(self._registry.keys()))

    def has(self, source_type: str) -> bool:
        """Check if a connector type is registered."""
        return source_type.lower().strip() in self._registry


# Global default instance
connector_registry = ConnectorRegistry()
