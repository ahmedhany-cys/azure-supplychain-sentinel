"""``python -m sentinel.api`` - run the API with safe defaults (loopback only)."""

import os

import uvicorn


def main() -> None:
    host = os.environ.get("SENTINEL_API_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINEL_API_PORT", "8000"))
    uvicorn.run(
        "sentinel.api.main:app", host=host, port=port, proxy_headers=False, server_header=False
    )


if __name__ == "__main__":
    main()
