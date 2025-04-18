"""
Scanner module for malware detection.

This module defines a Scanner class that performs file-based malware detection
using known signatures.
"""

import os
import hashlib
import json

class Scanner:
    """Class for scanning files and detecting possible malware."""

    def __init__(self):
        """Initialize the scanner with malware signatures and common settings."""
        self.signatures_file = os.path.join("signatures", "signatures.json")
        self.signatures = self.load_signatures()

        # Common file extensions used by malware
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1',
            '.hta', '.jar', '.pif', '.dll'
        }

        # Directories frequently targeted by malware
        self.quick_scan_dirs = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            "/tmp",
            "/var/tmp"
        ]

    def load_signatures(self):
        """
        Load malware signatures from the local database.

        Returns:
            dict: Dictionary of known malware file hashes and their names.
        """
        try:
            if os.path.exists(self.signatures_file):
                with open(self.signatures_file, 'r') as f:
                    return json.load(f)
            else:
                # Create a default signature file if not present
                sample_signatures = {
                    "44d88612fea8a8f36de82e1278abb02f": "Eicar Test File",
                    "e4968ef99266df7c9a1f0637d2389dab": "Sample Malware 1",
                    "f5bc7fcc7f5b5579bd349f7f52c8e19e": "Sample Malware 2",
                }
                with open(self.signatures_file, 'w') as f:
                    json.dump(sample_signatures, f, indent=4)
                return sample_signatures
        except Exception as e:
            print(f"[!] Error loading signatures: {e}")
            return {}

    def update_signatures(self, new_signatures):
        """
        Merge new malware signatures into the existing database.

        Args:
            new_signatures (dict): Dictionary of new malware signatures to add.
        """
        signatures = self.load_signatures()
        signatures.update(new_signatures)

        try:
            with open(self.signatures_file, 'w') as f:
                json.dump(signatures, f, indent=4)
            self.signatures = signatures
            print(f"[✓] Updated signatures database with {len(new_signatures)} new entries.")
        except Exception as e:
            print(f"[!] Error updating signatures: {e}")

    def calculate_file_hash(self, file_path):
        """
        Compute the MD5 hash of a file's content.

        Args:
            file_path (str): Path to the file

        Returns:
            str or None: MD5 hash if successful, None on failure
        """
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None

    def is_file_suspicious(self, file_path):
        """
        Determine if a file is suspicious based on signature matching.

        Args:
            file_path (str): Path to the file

        Returns:
            bool: True if file is suspicious, False otherwise
        """
        try:
            # Skip non-regular files
            if not os.path.isfile(file_path):
                return False

            # Check the file extension for high-risk
            extension = os.path.splitext(file_path)[1].lower()
            if extension in self.suspicious_extensions:
                file_hash = self.calculate_file_hash(file_path)
                if file_hash:
                    # Match against known malware signatures
                    if file_hash in self.signatures:
                        print(f"[!] Malware signature match: {self.signatures[file_hash]}")
                        return True

                    # Hidden executable
                    try:
                        is_hidden = os.path.basename(file_path).startswith('.')
                        if extension in ['.exe', '.scr', '.bat'] and is_hidden:
                            print(f"[!] Suspicious hidden executable: {file_path}")
                            return True
                    except:
                        pass

            return False

        except Exception as e:
            print(f"[!] Error analyzing file {file_path}: {e}")
            return False

    def scan_directory(self, directory, quick=False):
        """
        Recursively scan a directory for suspicious files.

        Args:
            directory (str): Directory path to scan.
            quick (bool): If True, only scan common malware locations.

        Returns:
            list: List of paths to suspicious files.
        """
        suspicious_files = []

        # Determine which directories to scan based on quick flag
        if quick:
            directories_to_scan = [d for d in self.quick_scan_dirs if os.path.exists(d)]
            print(f"[*] Performing quick scan of common locations...")
        else:
            directories_to_scan = [directory]
            print(f"[*] Starting deep scan of {directory}...")

        total_files = 0  # File counter for progress updates

        # Walk through each directory and scan each file
        for scan_dir in directories_to_scan:
            for root, _, files in os.walk(scan_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    total_files += 1

                    # Show progress every 100 files
                    if total_files % 100 == 0:
                        print(f"[*] Scanned {total_files} files...", end="\r")

                    try:
                        if self.is_file_suspicious(file_path):
                            suspicious_files.append(file_path)
                            print(f"[!] Suspicious file detected: {file_path}")
                    except Exception as e:
                        print(f"[!] Error scanning {file_path}: {e}")

        print(f"[✓] Scan complete. Scanned {total_files} files.")
        return suspicious_files
