import os
import hashlib
import time
import sched
import json
import difflib
import threading

# Path to store file hashes and file contents
hash_db_path = "file_hashes.json"
content_db_path = "file_contents.json"

# Flag to control monitoring loop
monitoring_active = True

def calculate_file_hash(filepath):
    """Calculate SHA-512 hash of a file."""
    hasher = hashlib.sha512()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def read_file_content(filepath):
    """Read file content (only for text files)."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.readlines()  # Returns content as a list of lines
    except:
        return None  # Return None for binary files

def save_json(data, filepath):
    """Save data to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

def load_json(filepath):
    """Load data from a JSON file."""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def generate_baseline(directory):
    """Generate a baseline of file hashes and contents."""
    file_hashes = {}
    file_contents = {}

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hashes[filepath] = calculate_file_hash(filepath)
            file_contents[filepath] = read_file_content(filepath)

    save_json(file_hashes, hash_db_path)
    save_json(file_contents, content_db_path)
    print("✅ Baseline hash database created successfully.")

def check_integrity(directory):
    """Check file integrity by comparing with the stored hash database."""
    if not os.path.exists(hash_db_path) or not os.path.exists(content_db_path):
        print("No baseline found. Please generate a baseline first.")
        return
    
    saved_hashes = load_json(hash_db_path)
    saved_contents = load_json(content_db_path)
    current_hashes = {}
    current_contents = {}

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            current_hashes[filepath] = calculate_file_hash(filepath)
            current_contents[filepath] = read_file_content(filepath)

    # Check for modifications and new files
    for filepath, new_hash in current_hashes.items():
        if filepath in saved_hashes:
            if saved_hashes[filepath] != new_hash:
                print(f"🟡 [MODIFIED] {filepath}")
                # Identify content changes
                old_content = saved_contents.get(filepath)
                new_content = current_contents.get(filepath)
                
                if old_content and new_content:
                    diff = difflib.unified_diff(old_content, new_content, lineterm="")
                    print("\n🔍 CONTENT CHANGES:")
                    for line in diff:
                        print(line.strip())
        else:
            print(f"🟢 [NEW FILE] {filepath}")

    # Check for deleted files
    for filepath in saved_hashes.keys():
        if filepath not in current_hashes:
            print(f"🔴 [DELETED] {filepath}")

def monitor_user_input():
    """Monitors user input to allow stopping the integrity check."""
    global monitoring_active
    while monitoring_active:
        user_input = input("Type 'exit' to stop monitoring: ").strip().lower()
        if user_input == "exit":
            monitoring_active = False
            print("\n🛑 Stopping integrity check...")
            break

def schedule_regular_scans(interval, directory):
    """Continuously scan files at regular intervals."""
    global monitoring_active
    scheduler = sched.scheduler(time.time, time.sleep)
    
    def scan():
        if not monitoring_active:
            return
        print("\n🔍 Running integrity check...")
        check_integrity(directory)
        scheduler.enter(interval, 1, scan)

    # Start user input monitoring in a separate thread
    user_thread = threading.Thread(target=monitor_user_input, daemon=True)
    user_thread.start()

    scheduler.enter(0, 1, scan)
    try:
        scheduler.run()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped manually.")

if __name__ == "__main__":
    target_directory = r"C:\Users\nirma\Downloads\My files test"  # Change to the directory you want to monitor

    print("1️⃣ Generate Baseline")
    print("2️⃣ Start Monitoring")
    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        generate_baseline(target_directory)
    elif choice == "2":
        scan_interval = 10  # Scan every 10 seconds (adjust as needed)
        schedule_regular_scans(scan_interval, target_directory)
    else:
        print("❌ Invalid choice. Exiting.")
