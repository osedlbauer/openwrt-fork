#!/usr/bin/python3

import json
import xml.etree.ElementTree as ET
import uuid
import argparse


CYCLONE_SPEC_VERSION = "1.5"


def convert_pkg_to_dict():
    package_dict = {
        "packages": []
    }
    package = {}
    last_key = None
    with open("packages/Packages", "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("Package: "):
                if package:
                    package_dict["packages"].append(package)
                package = {}
                key, value = line.split(": ", 1)
                key = key.strip()
                value = value.strip()
                package[key] = value
                last_key = key
            elif line:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    key = key.strip()
                    value = value.strip()
                    package[key] = value
                    last_key = key
                elif package and last_key:
                    package[last_key] += " " + line

    if package:
        package_dict["packages"].append(package)
    return package_dict


def generate_cyclonedx(package_dict):
    random_uuid = str(uuid.uuid4())
    sbom_cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONE_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{random_uuid}",
        "version": 1,
        "components": []
    }
    for package in package_dict["packages"]:
        if "Package" in package:
            component = {
                "name": package.get("Package"),
                "type": "application"
            }

            if "Version" in package:
                component["version"] = package["Version"]

            if "License" in package:
                component["licenses"] = [
                    {
                        "license": {
                            "name": package["License"]
                        }
                    }
                ]

            if "CPE-ID" in package and "Version" in package:
                component["cpe"] = package["CPE-ID"]+":"+package["Version"]

            sbom_cyclonedx["components"].append(component)
    return sbom_cyclonedx

def generate_sbom(package_dict, sbom_format):
    if sbom_format == "CycloneDX":
        return generate_cyclonedx(package_dict)


def output_sbom(sbom_dict, output_format):
    if output_format == "json":
        print(json.dumps(sbom_dict))
    elif output_format == "xml":
        print("TODO")
    else:
        print("Unsupported output format. Please choose either 'json' or 'xml'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SBOM.")
    parser.add_argument("--output-format", choices=["json", "xml"], default="json",
                        help="Output format for the SBOM (default: json)")
    parser.add_argument("--sbom-format", choices=["CycloneDX"], default="CycloneDX",
                        help="SBOM format (default: CycloneDX)")
    args = parser.parse_args()

    packages = convert_pkg_to_dict()
    sbom = generate_sbom(packages, args.sbom_format)
    output_sbom(sbom, args.output_format)


# packages = convert_pkg_to_dict()
# cyclonedx = generate_sbom(packages)

# print(json.dumps(cyclonedx))
