# oo7 Python Bindings

Python bindings for [oo7](../client/), providing access to Secret Service API on Linux. Automatically uses a file-based keyring when running in a sandboxed environment.

## Installation

```bash
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
maturin develop
```

## Usage

```python
import asyncio
import oo7

async def main():
    # Create keyring
    keyring = await oo7.Keyring.new()

    # Store a secret
    await keyring.create_item(
        "My Password",
        {"application": "myapp", "username": "alice"},
        b"secret-password",
        replace=True
    )

    # Search for items
    items = await keyring.search_items({"application": "myapp"})
    for item in items:
        secret = await item.secret()
        print(f"Secret: {secret}")

    # Clean up
    await keyring.delete({"application": "myapp"})

asyncio.run(main())
```

## Running Tests

```bash
pytest
```

## Examples

See `tests/test_keyring.py` for more examples.

## License

MIT
