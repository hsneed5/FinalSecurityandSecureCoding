import os
import re
import argparse
import logging
from pathlib import Path

# Logging Configuration

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "scanner.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Regex Patterns for Secret Detection

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),

    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),

    "Generic Password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-=]{6,}['\"]?"
    ),

    "JWT Token": re.compile(
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    ),

    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),

    "Private Key": re.compile(
        r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? PRIVATE KEY-----"
    ),

    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),

    "Stripe API Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}")
}

# Supported File Extensions

SUPPORTED_EXTENSIONS = {
    ".txt",
    ".py",
    ".js",
    ".json",
    ".env",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".java",
    ".php"
}

# Scan a Single File

def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = pattern.findall(line)

                    if matches:
                        for match in matches:
                            # Handle regex groups
                            matched_value = match
                            if isinstance(match, tuple):
                                matched_value = " ".join(match)

                            findings.append({
                                "file": str(file_path),
                                "line": line_number,
                                "type": secret_type,
                                "match": line.strip()
                            })

                            logging.warning(
                                f"Potential secret found | "
                                f"File: {file_path} | "
                                f"Line: {line_number} | "
                                f"Type: {secret_type}"
                            )

    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")

    return findings

# Scan Directory Recursively

def scan_directory(directory_path):
    all_findings = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = Path(root) / file_name

            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                logging.info(f"Scanning file: {file_path}")
                all_findings.extend(scan_file(file_path))

    return all_findings

# Print Findings Report

def print_report(findings):
    print("\n" + "=" * 70)
    print("SECRET SCAN REPORT")
    print("=" * 70)

    if not findings:
        print("No secrets detected.")
        return

    for finding in findings:
        print(f"File       : {finding['file']}")
        print(f"Line       : {finding['line']}")
        print(f"Secret Type: {finding['type']}")
        print(f"Matched    : {finding['match']}")
        print("-" * 70)

    print(f"Total Findings: {len(findings)}")

# Main CLI Logic

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for scanning files and directories for hardcoded secrets."
    )

    parser.add_argument(
        "path",
        help="Path to a file or directory to scan"
    )

    args = parser.parse_args()

    target_path = Path(args.path)

    if not target_path.exists():
        print(f"Error: Path does not exist -> {target_path}")
        return

    logging.info(f"Starting scan on: {target_path}")

    findings = []

    if target_path.is_file():
        findings.extend(scan_file(target_path))

    elif target_path.is_dir():
        findings.extend(scan_directory(target_path))

    print_report(findings)

    logging.info("Scan completed")


if __name__ == "__main__":
    main()
