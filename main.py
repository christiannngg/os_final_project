"""
Malware Detection and Removal Tool
A CLI tool for detecting, quarantining, and removing malware from a system.
"""

import os
import sys
import argparse
from scanner import Scanner
from process_analyzer import ProcessAnalyzer
from quarantine import QuarantineManager

def create_directories():
    """Ensure required directories for signatures and quarantine exist."""
    os.makedirs("signatures", exist_ok=True)
    os.makedirs("quarantine", exist_ok=True)

def main():
    """Main entry point for the malware detection CLI tool."""

    # Initialize argument parser for the CLI
    parser = argparse.ArgumentParser(
        description="Malware Detection and Removal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python main.py scan -p /Users/christiangonzalez/Downloads"
    )

    # Define subcommands: scan, processes, quarantine
    subparsers = parser.add_subparsers(des="command", help="Commands")

    # ------------------- Scan Command ------------------- #
    scan_parser = subparsers.add_parser("scan", help="Scan for malware")
    scan_parser.add_argument(
        "-p", "--path",
        default=os.path.expanduser("~"),
        help="Directory path to scan (default: home directory)"
    )
    scan_parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Perform a quick scan (scan only common locations)"
    )

    # ------------------- Processes Command ------------------- #
    process_parser = subparsers.add_parser("processes", help="Analyze running processes")
    process_parser.add_argument(
        "-n", "--network",
        action="store_true",
        help="Show network connections"
    )

    # ------------------- Quarantine Command ------------------- #
    quarantine_parser = subparsers.add_parser("quarantine", help="Manage quarantined items")
    quarantine_parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List quarantined items"
    )
    quarantine_parser.add_argument(
        "-r", "--restore",
        type=int,
        help="Restore quarantined item by ID"
    )
    quarantine_parser.add_argument(
        "-d", "--delete",
        type=int,
        help="Permanently delete quarantined item by ID"
    )
    quarantine_parser.add_argument(
        "--delete-all",
        action="store_true",
        help="Delete all quarantined items"
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Set up necessary directories before executing commands
    create_directories()

    # ------------------- Command: scan ------------------- #
    if args.command == "scan":
        scanner = Scanner()
        sus_files = scanner.scan_directory(args.path, quick=args.quick)

        if sus_files:
            print(f"{sus_files} suspicious files")
            quarantine_mngr = QuarantineManager()

            # Quarantine each suspicious file
            for file_path in sus_files:
                print(f"Adding {file_path} to quarantine...")
                quarantine_mngr.quarantine_file(file_path)
        else:
            print("\n[✓] No suspicious files found.")

    # ------------------- Command: processes ------------------- #
    elif args.command == "processes":
        analyzer = ProcessAnalyzer()
        suspicious_processes = analyzer.analyze(network=args.network)

        if suspicious_processes:
            print(f"\n[!] Found {len(suspicious_processes)} suspicious processes.")
            for p_id, name, reason in suspicious_processes:
                print(f"[*] PID: {p_id}, Name: {name}, Reason: {reason}")
                print(f"    To terminate: sudo kill {p_id}")
        else:
            print("\n[✓] No suspicious processes detected.")

    # ------------------- Command: quarantine ------------------- #
    elif args.command == "quarantine":
        quarantine_mgnr = QuarantineManager()

        if args.list:
            quarantine_mgnr.list_quarantine_files()
        elif args.restore is not None:
            quarantine_mgnr.restore_file(args.restore)
        elif args.delete is not None:
            quarantine_mgnr.delete_file(args.delete)
        elif args.delete_all:
            quarantine_mgnr.delete_all_files()
        else:
            # Display help if no quarantine option is chosen
            quarantine_parser.print_help()

    # ------------------- Default (no command provided) ------------------- #
    else:
        parser.print_help()

# Safely run the main function, handle interrupts and unexpected errors
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)



        

