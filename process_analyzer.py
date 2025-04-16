"""
Process analyzer module for detecting suspicious processes.

This module inspects running system processes and network connections
to find indicators of likely malware or unwanted activity.
"""


import subprocess
import re


class ProcessAnalyzer:
    """Class for analyzing running processes and network connections."""

    def __init__(self):
        """Initialize process analyzer with keywords, paths, and threats."""
        self.suspicious_keywords = [
            "miner", "coin", "virus", "malware", "hack", "trojan",
            "backdoor", "keylog", "spyware", "rootkit", "exploit"
        ]

        # Common suspicious directories used by malware
        self.suspicious_paths = [
            "/tmp/", "/var/tmp/", "/private/tmp/"
        ]

        # Example malicious domains/IPs (placeholder data)
        self.suspicious_connections = [
            "evil.com", "malware.org", "192.168.0.666"
        ]

    def get_running_processes(self):
        """
        Retrieve a list of running processes.

        Returns:
            list: List of dictionaries, each representing a process.
        """
        try:
            result = subprocess.run(
                ["ps", "-e", "-o", "pid,ppid,user,%cpu,%mem,command"],
                capture_output=True, text=True, check=True
            )

            processes = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip the header row

            for line in lines:
                fields = re.split(r'\s+', line.strip(), maxsplit=5)
                if len(fields) >= 6:
                    p_id, pp_id, user, cpu, mem, command = fields
                    processes.append({
                        'pid': p_id,
                        'ppid': pp_id,
                        'user': user,
                        'cpu': cpu,
                        'mem': mem,
                        'command': command
                    })

            return processes
        except Exception as e:
            print(f"[!] Error getting process list: {e}")
            return []

    def get_network_connections(self):
        """
        Get a list of active network connections.

        Returns:
            list: List of dictionaries, each representing a network connection.
        """
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True, text=True, check=True
            )

            connections = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header row

            for line in lines:
                fields = re.split(r'\s+', line.strip())
                if len(fields) >= 9:
                    process = fields[0]
                    p_id = fields[1]
                    user = fields[2]
                    protocol = fields[4]
                    connection = fields[8]

                    connections.append({
                        'process': process,
                        'pid': p_id,
                        'user': user,
                        'protocol': protocol,
                        'connection': connection
                    })

            return connections
        except Exception as e:
            print(f"[!] Error getting network connections: {e}")
            return []

    def is_process_suspicious(self, process):
        """
        Determine whether a process appears suspicious.

        Args:
            process (dict): Process metadata

        Returns:
            tuple: (bool, str) indicating suspicion and reason
        """
        command = process['command'].lower()

        # Check for malicious keywords in the command
        for keyword in self.suspicious_keywords:
            if keyword in command:
                return True, f"Suspicious keyword '{keyword}' in command"

        # Check for execution from suspicious directories
        for path in self.suspicious_paths:
            if path in command:
                return True, f"Running from suspicious location '{path}'"

        # Flag if the process uses high CPU or memory
        try:
            cpu = float(process['cpu'])
            mem = float(process['mem'])
            if cpu > 90 or mem > 80:
                return True, f"High resource usage (CPU: {cpu}%, MEM: {mem}%)"
        except:
            pass

        return False, ""

    def is_connection_suspicious(self, connection, process_map):
        """
        Determine whether a network connection is suspicious.

        Args:
            connection (dict): Connection metadata
            process_map (dict): Mapping of pid -> process info

        Returns:
            tuple: (bool, str) indicating suspicion and reason
        """
        conn_str = connection['connection'].lower()

        # Check for suspicious domains/IPs
        for domain in self.suspicious_connections:
            if domain.lower() in conn_str:
                return True, f"Connection to suspicious domain/IP {domain}"

        # Cross reference with suspicious processes
        p_id = connection['pid']
        if p_id in process_map:
            suspicious, reason = self.is_process_suspicious(process_map[p_id])
            if suspicious:
                return True, f"Suspicious process making connection: {reason}"

        return False, ""

    def analyze(self, network=False):
        """
        Analyze running processes and optionally network connections.

        Args:
            network (bool): Whether to include network connection analysis.

        Returns:
            list: List of suspicious items (pid, name, reason)
        """
        suspicious_items = []

        print("[*] Analyzing running processes...")
        processes = self.get_running_processes()
        process_map = {p['pid']: p for p in processes}

        for process in processes:
            suspicious, reason = self.is_process_suspicious(process)
            if suspicious:
                suspicious_items.append((
                    process['pid'],
                    process['command'].split()[0],
                    reason
                ))

        if network:
            print("[*] Analyzing network connections...")
            connections = self.get_network_connections()

            for connection in connections:
                suspicious, reason = self.is_connection_suspicious(connection, process_map)
                if suspicious:
                    pid = connection['pid']
                    process_name = connection['process']
                    conn_info = connection['connection']
                    suspicious_items.append((
                        pid,
                        process_name,
                        f"{reason} - Connection: {conn_info}"
                    ))

        return suspicious_items


