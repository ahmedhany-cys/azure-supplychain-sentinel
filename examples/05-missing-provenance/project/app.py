"""Minimal service entry point used as release content in a demonstration scenario."""


def health() -> dict[str, str]:
    return {"status": "ok"}
