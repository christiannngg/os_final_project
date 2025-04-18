# Malware Removal Project (macOS)

This project is a command-line malware detection and removal tool developed in Python. It can:

- Detect files that match known malware signatures
- Quarantine and isolate suspicious files
- Analyze system processes and network activity
- Restore or permanently delete quarantined items

This project is designed and developed for a Final Operating Systems and Networking Final Project

---

## Prerequisites

Make sure the following are available:


- Python 3.8+ (`python3 --version`)
- Terminal/IDE
- The following files and folders in the project root:

main.py scanner.py process_analyzer.py quarantine.py signatures/ # contains signatures.db (JSON format) quarantine/ # auto-created by the program

---

## Step 1: Create a Safe Test Environment

We'll simulate malware using dummy files.

1.1. Create a test directory
mkdir ~/malware_test_env

1.2. Add a dummy file that looks suspicious
cp /bin/ls ~/malware_test_env/fake_malware.exe (The .exe extension will trigger the malware scanner)

## Step 2: Simulate a Malware Signature Match
2.1. Calculate the dummy file’s MD5 hash
Open a Python shell and run:

python3
import hashlib
hashlib.md5(open("/Users/YOUR_NAME/malware_test_env/fake_malware.exe", "rb").read()).hexdigest()
Tip: (Replace /Users/YOUR_NAME/... with the correct file path. Save the resulting hash)

2.2. Add the hash to the signature database
Open signatures/signatures.db and add:

json:
{
  "your_calculated_hash_here": "Test Fake Malware"
}
(Make sure the file remains valid JSON. If needed, separate entries with commas)

## Step 3: Run the Malware Scanner
3.1. Deep scan the test directory
python3 main.py scan -p ~/malware_test_env

Expected behavior:
Suspicious file detected and quarantined
Moved to the quarantine/ folder
Index updated in quarantine/index.json

## Step 4: Analyze Running Processes
4.1. Simulate a suspicious process
echo 'while true; do echo "Running miner..."; sleep 10; done' > ~/malware_test_env/miner_sim.sh
chmod +x ~/malware_test_env/miner_sim.sh
~/malware_test_env/miner_sim.sh &
4.2. Analyze processes
python3 main.py processes

Expected output:
[*] PID: 12345, Name: bash, Reason: Suspicious keyword 'miner' in command

## Step 5: Manage Quarantine
5.1. List quarantined files
python3 main.py quarantine -l

5.2. Restore a quarantined file
python3 main.py quarantine -r 1
Tip: Verify the file is restored to ~/malware_test_env.

5.3. Delete one file from quarantine
python3 main.py quarantine -d 1

5.4. Delete all quarantined files
python3 main.py quarantine --delete-all

## Step 6: Cleanup
To Stop the simulated process:
pkill -f miner_sim.sh

To delete test directory:
rm -rf ~/malware_test_env

Notes
Do not scan or quarantine files from critical system folders such as /System or /usr/bin.
Only test with files you created or understand.
The quarantine manager includes full restore and delete support.

Author
Christian Gonzalez
