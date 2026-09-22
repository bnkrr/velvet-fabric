#!/usr/bin/env python3
"""Copy a minimal example with fresh keys/UUIDs; retain its routing configuration."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("example", choices=("static_minimal", "dynamic_minimal"))
    parser.add_argument("output", type=Path, help="new directory for private runtime configs")
    parser.add_argument("--babel", type=Path, help="absolute babel-rs path on the nodes")
    args = parser.parse_args()
    if args.babel is not None and not args.babel.is_absolute():
        parser.error("--babel must be an absolute path")
    if args.output.exists():
        parser.error("output already exists; choose a new directory to avoid replacing keys")

    def wg(*command, data=None):
        return subprocess.check_output(["wg", *command], input=data, text=True).strip()

    replacements = {"<FABRIC_PSK>": wg("genpsk")}
    for node in "ABC":
        private = wg("genkey")
        replacements[f"<{node}_PRIVATE_KEY>"] = private
        replacements[f"<{node}_PUBLIC_KEY>"] = wg("pubkey", data=private + "\n")

    templates = Path(__file__).resolve().parent / args.example
    configs = {}
    for node in "abc":
        text = (templates / f"{node}.json").read_text()
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        config = json.loads(text)
        config["node"]["uid"]["uuid"] = str(uuid.uuid4())
        if args.babel is not None and "babel" in config:
            config["babel"]["executable"] = str(args.babel)
        configs[node] = config

    args.output.mkdir(mode=0o700, parents=True)
    for node, config in configs.items():
        path = args.output / f"{node}.json"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
    print(f"Prepared {args.example} in {args.output}")


if __name__ == "__main__":
    main()
