"""
Quarantine management module for isolating and removing malware.

This module handles moving suspicious files to a quarantine area,
restoring them when needed, or permanently deleting them.
"""

import os
import shutil
import json
import base64
import datetime


class QuarantineManager:
    """Class for managing quarantined files."""

    def __init__(self):
        """Initialize the quarantine manager and load the quarantine index."""
        self.quarantine_dir = "quarantine"
        self.index_file = os.path.join(self.quarantine_dir, "index.json")

        # Make sure the quarantine directory exists
        os.makedirs(self.quarantine_dir, exist_ok=True)

        # Load existing index of quarantined files
        self.index = self.load_index()

    def load_index(self):
        """
        Load the quarantine index from the JSON file.

        Returns:
            dict: Dictionary mapping quarantine IDs to file metadata
        """
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Error loading quarantine index: {e}")
                return {}
        else:
            return {}

    def save_index(self):
        """Save the current quarantine index to the JSON file."""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.index, f, indent=4)
        except Exception as e:
            print(f"[!] Error saving quarantine index: {e}")

    def quarantine_file(self, file_path):
        """
        Quarantine a suspicious file.

        Args:
            file_path (str): Path to the file to quarantine

        Returns:
            bool: True if quarantine was successful, False otherwise
        """
        try:
            file_path = os.path.abspath(file_path)

            # Make sure the file exists before proceeding
            if not os.path.exists(file_path):
                print(f"[!] File not found: {file_path}")
                return False

            # Create a unique quarantine ID
            q_id = len(self.index) + 1

            # Encode filename to avoid naming conflicts
            encoded_name = base64.b64encode(os.path.basename(file_path).encode()).decode()
            quarantine_file = os.path.join(self.quarantine_dir, f"quarantined_{q_id}_{encoded_name}")

            # Move the file into the quarantine directory
            shutil.move(file_path, quarantine_file)

            # Record the file in the quarantine index
            self.index[str(q_id)] = {
                "original_path": file_path,
                "quarantine_path": quarantine_file,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "size": os.path.getsize(quarantine_file)
            }

            self.save_index()

            print(f"[✓] File quarantined successfully (ID: {q_id}).")
            return True

        except Exception as e:
            print(f"[!] Error quarantining file: {e}")
            return False

    def restore_file(self, q_id):
        """
        Restore a quarantined file to its original location.

        Args:
            q_id (int): ID of the file to restore

        Returns:
            bool: True if restored successfully, False otherwise
        """
        q_id_str = str(q_id)

        if q_id_str not in self.index:
            print(f"[!] Quarantine ID {q_id} not found.")
            return False

        try:
            file_info = self.index[q_id_str]
            original_path = file_info["original_path"]
            quarantine_path = file_info["quarantine_path"]

            # Create original directory if it no longer exists
            original_dir = os.path.dirname(original_path)
            if not os.path.exists(original_dir):
                os.makedirs(original_dir, exist_ok=True)

            # Move the file back to its original location
            shutil.move(quarantine_path, original_path)

            # Remove from index
            del self.index[q_id_str]
            self.save_index()

            print(f"[✓] File restored successfully to {original_path}")
            print("[!] WARNING: This file was previously identified as malicious.")
            print("    Only restore if you are confident it is safe.")
            return True

        except Exception as e:
            print(f"[!] Error restoring file: {e}")
            return False

    def delete_file(self, q_id):
        """
        Permanently delete a quarantined file.

        Args:
            q_id (int): ID of the file to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        q_id_str = str(q_id)

        if q_id_str not in self.index:
            print(f"[!] Quarantine ID {q_id} not found.")
            return False

        try:
            file_info = self.index[q_id_str]
            quarantine_path = file_info["quarantine_path"]

            # Remove file from disk
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)

            # Remove from index
            del self.index[q_id_str]
            self.save_index()

            print(f"[✓] Quarantined file (ID: {q_id}) permanently deleted.")
            return True

        except Exception as e:
            print(f"[!] Error deleting file: {e}")
            return False

    def delete_all_files(self):
        """
        Permanently delete all quarantined files.

        Returns:
            bool: True if all files were deleted successfully, False otherwise
        """
        try:
            count = 0

            # Iterate over a copy of the keys to modify the dictionary during loop
            for q_id in list(self.index.keys()):
                file_info = self.index[q_id]
                quarantine_path = file_info["quarantine_path"]

                # Delete the file if it exists
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)

                del self.index[q_id]
                count += 1

            self.save_index()

            print(f"[✓] {count} quarantined files permanently deleted.")
            return True

        except Exception as e:
            print(f"[!] Error deleting all files: {e}")
            return False

    def list_quarantined_files(self):
        """
        Display a table of all quarantined files.
        """
        if not self.index:
            print("[*] No files in quarantine.")
            return

        print("\n=== Quarantined Files ===")
        print(f"{'ID':<5} {'Original Path':<50} {'Date':<20} {'Size':<10}")
        print("-" * 85)

        for q_id, file_info in self.index.items():
            size_kb = file_info["size"] / 1024
            size_str = f"{size_kb:.2f} KB"
            print(f"{q_id:<5} {file_info['original_path']:<50} {file_info['timestamp']:<20} {size_str:<10}")

        print("\nTo restore: python main.py quarantine -r <ID>")
        print("To delete:  python main.py quarantine -d <ID>")
