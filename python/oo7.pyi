"""
Type stubs for oo7

This module provides async-only Python bindings to the oo7 Rust crate,
which implements the Secret Service API on Linux. Automatically uses a
file-based keyring when running in a sandboxed environment.
"""

from typing import Dict, List, Union

class Keyring:
    """
    A Secret Service or file-backed keyring implementation.

    The keyring automatically selects between file-based (for sandboxed apps)
    and DBus-based backends.
    """

    @staticmethod
    async def new() -> Keyring:
        """
        Create a new Keyring instance.

        Returns:
            Keyring: A new keyring instance

        Raises:
            RuntimeError: If keyring initialization fails
        """
        ...

    async def unlock(self) -> None:
        """
        Unlock the keyring.

        Returns:
            None

        Raises:
            RuntimeError: If unlock operation fails
        """
        ...

    async def lock(self) -> None:
        """
        Lock the keyring.

        Returns:
            None

        Raises:
            RuntimeError: If lock operation fails
        """
        ...

    async def is_locked(self) -> bool:
        """
        Check if the keyring is locked.

        Returns:
            bool: True if locked, False otherwise

        Raises:
            RuntimeError: If the check fails
        """
        ...

    async def delete(self, attributes: Dict[str, str]) -> None:
        """
        Delete items matching the given attributes.

        Args:
            attributes: Dictionary of attribute key-value pairs to match

        Returns:
            None

        Raises:
            RuntimeError: If deletion fails
        """
        ...

    async def items(self) -> List[Item]:
        """
        Retrieve all items in the keyring.

        Returns:
            list[Item]: List of all items

        Raises:
            RuntimeError: If retrieval fails
        """
        ...

    async def create_item(
        self,
        label: str,
        attributes: Dict[str, str],
        secret: Union[bytes, str],
        replace: bool
    ) -> None:
        """
        Create a new item in the keyring.

        Args:
            label: Human-readable label for the item
            attributes: Dictionary of attribute key-value pairs
            secret: The secret to store (bytes or str)
            replace: If True, replace existing items with matching attributes

        Returns:
            None

        Raises:
            RuntimeError: If item creation fails
            ValueError: If secret is not bytes or str
        """
        ...

    async def search_items(self, attributes: Dict[str, str]) -> List[Item]:
        """
        Search for items matching the given attributes.

        Args:
            attributes: Dictionary of attribute key-value pairs to match

        Returns:
            list[Item]: List of matching items

        Raises:
            RuntimeError: If search fails
        """
        ...


class Item:
    """
    A secret item in the keyring.

    Items have a label, attributes for searching, and a secret value.
    They can be locked/unlocked individually (though some backends may
    lock/unlock the entire collection).
    """

    async def label(self) -> str:
        """
        Get the item's label.

        Returns:
            str: The item label

        Raises:
            RuntimeError: If retrieval fails or item is locked
        """
        ...

    async def set_label(self, label: str) -> None:
        """
        Set the item's label.

        Args:
            label: New label for the item

        Returns:
            None

        Raises:
            RuntimeError: If setting fails or item is locked
        """
        ...

    async def attributes(self) -> Dict[str, str]:
        """
        Get the item's attributes.

        Returns:
            dict: Dictionary of attribute key-value pairs

        Raises:
            RuntimeError: If retrieval fails or item is locked
        """
        ...

    async def set_attributes(self, attributes: Dict[str, str]) -> None:
        """
        Set the item's attributes.

        Args:
            attributes: New attributes for the item

        Returns:
            None

        Raises:
            RuntimeError: If setting fails or item is locked
        """
        ...

    async def secret(self) -> bytes:
        """
        Get the item's secret.

        Returns:
            bytes: The secret value as bytes

        Raises:
            RuntimeError: If retrieval fails or item is locked
        """
        ...

    async def set_secret(self, secret: Union[bytes, str]) -> None:
        """
        Set the item's secret.

        Args:
            secret: New secret value (bytes or str)

        Returns:
            None

        Raises:
            RuntimeError: If setting fails or item is locked
            ValueError: If secret is not bytes or str
        """
        ...

    async def is_locked(self) -> bool:
        """
        Check if the item is locked.

        Returns:
            bool: True if locked, False otherwise

        Raises:
            RuntimeError: If the check fails
        """
        ...

    async def lock(self) -> None:
        """
        Lock the item.

        Returns:
            None

        Raises:
            RuntimeError: If lock operation fails
        """
        ...

    async def unlock(self) -> None:
        """
        Unlock the item.

        Returns:
            None

        Raises:
            RuntimeError: If unlock operation fails
        """
        ...

    async def delete(self) -> None:
        """
        Delete the item.

        Returns:
            None

        Raises:
            RuntimeError: If deletion fails
        """
        ...

    async def created(self) -> float:
        """
        Get the UNIX timestamp when the item was created.

        Returns:
            float: Seconds since UNIX epoch

        Raises:
            RuntimeError: If retrieval fails or item is locked
        """
        ...

    async def modified(self) -> float:
        """
        Get the UNIX timestamp when the item was last modified.

        Returns:
            float: Seconds since UNIX epoch

        Raises:
            RuntimeError: If retrieval fails or item is locked
        """
        ...
