"""Check the resolved feature graph supporting temporary rmcp exceptions."""

import json
import sys

FORBIDDEN_FEATURES = {
    "auth",
    "transport-streamable-http-client",
    "transport-streamable-http-client-reqwest",
    "transport-streamable-http-client-unix-socket",
}


def check_metadata(metadata):
    try:
        packages = {package["id"] for package in metadata["packages"] if package["name"] == "rmcp"}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        if not packages or not packages <= nodes.keys():
            raise ValueError("Resolved rmcp metadata is missing")
        for package in sorted(packages):
            forbidden = FORBIDDEN_FEATURES.intersection(nodes[package]["features"])
            if forbidden:
                raise ValueError(f"rmcp advisory exception invalid: {package}: {', '.join(sorted(forbidden))}")
    except (KeyError, TypeError) as error:
        raise ValueError("Incomplete Cargo metadata") from error


if __name__ == "__main__":
    try:
        check_metadata(json.load(sys.stdin))
    except (ValueError, TypeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
