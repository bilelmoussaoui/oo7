"""
Tests for oo7 Python bindings
"""

import pytest
import oo7


@pytest.mark.asyncio
async def test_basic_operations():
    keyring = await oo7.Keyring.new()

    is_locked = await keyring.is_locked()
    assert isinstance(is_locked, bool)

    await keyring.create_item(
        "Test Password",
        {
            "application": "oo7-python-test",
            "username": "alice",
            "service": "example.com",
        },
        b"my-secret-password",
        replace=True,
    )

    items = await keyring.search_items({"application": "oo7-python-test"})
    assert len(items) == 1

    item = items[0]
    label = await item.label()
    assert label == "Test Password"

    attrs = await item.attributes()
    assert attrs["application"] == "oo7-python-test"
    assert attrs["username"] == "alice"
    assert attrs["service"] == "example.com"

    secret = await item.secret()
    assert secret == b"my-secret-password"

    created = await item.created()
    assert created > 0

    modified = await item.modified()
    assert modified > 0
    assert modified >= created

    is_locked = await item.is_locked()
    assert isinstance(is_locked, bool)

    await keyring.delete({"application": "oo7-python-test"})


@pytest.mark.asyncio
async def test_item_mutations():
    keyring = await oo7.Keyring.new()

    await keyring.create_item(
        "Original Label",
        {"application": "oo7-mutation-test", "version": "1.0"},
        "original-secret",
        replace=True,
    )

    items = await keyring.search_items({"application": "oo7-mutation-test"})
    item = items[0]

    await item.set_label("Updated Label")
    new_label = await item.label()
    assert new_label == "Updated Label"

    await item.set_attributes(
        {
            "application": "oo7-mutation-test",
            "version": "2.0",
            "new-field": "new-value",
        }
    )
    new_attrs = await item.attributes()
    assert new_attrs["version"] == "2.0"
    assert new_attrs["new-field"] == "new-value"

    await item.set_secret(b"new-secret-value")
    new_secret = await item.secret()
    assert new_secret == b"new-secret-value"

    await item.delete()

    items = await keyring.search_items({"application": "oo7-mutation-test"})
    assert len(items) == 0


@pytest.mark.asyncio
async def test_multiple_items():
    keyring = await oo7.Keyring.new()

    for i in range(3):
        await keyring.create_item(
            f"Test Item {i}",
            {
                "application": "oo7-multi-test",
                "index": str(i),
                "group": "test-group",
            },
            f"secret-{i}".encode(),
            replace=True,
        )

    items = await keyring.search_items({"application": "oo7-multi-test"})
    assert len(items) == 3

    # Search for specific item
    specific = await keyring.search_items(
        {"application": "oo7-multi-test", "index": "1"}
    )
    assert len(specific) == 1
    label = await specific[0].label()
    assert label == "Test Item 1"
    secret = await specific[0].secret()
    assert secret == b"secret-1"

    await keyring.delete({"application": "oo7-multi-test"})


@pytest.mark.asyncio
async def test_string_and_bytes_secrets():
    """Test that both string and bytes secrets work"""
    keyring = await oo7.Keyring.new()

    await keyring.create_item(
        "String Secret",
        {"application": "oo7-type-test", "type": "string"},
        "text-based-secret",
        replace=True,
    )

    await keyring.create_item(
        "Bytes Secret",
        {"application": "oo7-type-test", "type": "bytes"},
        b"\x00\x01\x02\x03\x04",
        replace=True,
    )

    items = await keyring.search_items({"application": "oo7-type-test"})
    assert len(items) == 2

    for item in items:
        attrs = await item.attributes()
        secret = await item.secret()

        if attrs["type"] == "string":
            assert secret == b"text-based-secret"
        elif attrs["type"] == "bytes":
            assert secret == b"\x00\x01\x02\x03\x04"

    await keyring.delete({"application": "oo7-type-test"})
