import os
import shutil
import sys

# Configuration for the 4 instances
instances = {
    "instance1": {"a": "tap0", "b": "tap1", "port": 5000},
    "instance2": {"a": "tap2", "b": "tap3", "port": 5002},
    "instance3": {"a": "tap11", "b": "tap12", "port": 5004},
    "instance4": {"a": "tap13", "b": "tap14", "port": 5006},
}

# Source directory (parent of current script execution context)
# We assume this script is run from /home/ketan/ngfw-final/final/Project_Final
# So source files are in /home/ketan/ngfw-final/final/
SOURCE_DIR = ".." 
DEST_BASE = "."

files_to_copy = {
    "forwarderws666.py": "forwarder.py",
    "decision3.py": "decision_engine.py",
    "dashboard_app.py": "dashboard.py",
    "fastclass.py": "fastclass.py",
    "sessions.db": "session.db",
    "l4_model.joblib": "l4_model.joblib",
    "model.cbm": "model.cbm",
    "encrypted_model.joblib": "encrypted_model.joblib",
    "plaintext_model.joblib": "plaintext_model.joblib",
}

dir_to_copy = "dashboard_components"

print(f"Starting setup in {os.getcwd()}...")

for instance_name, config in instances.items():
    dest_dir = os.path.join(DEST_BASE, instance_name)
    
    # Create directory
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"Created {dest_dir}")
    else:
        print(f"{dest_dir} already exists")

    # Copy files
    for src_file, dest_name in files_to_copy.items():
        src_path = os.path.join(SOURCE_DIR, src_file)
        dest_path = os.path.join(dest_dir, dest_name)
        
        if os.path.exists(src_path):
            shutil.copy2(src_path, dest_path)
            print(f"  Copied {src_file} -> {dest_name}")
        else:
            print(f"  WARNING: Source file {src_path} not found!")

    # Copy directory
    src_dir_path = os.path.join(SOURCE_DIR, dir_to_copy)
    dest_dir_path = os.path.join(dest_dir, dir_to_copy)
    if os.path.exists(src_dir_path):
        if os.path.exists(dest_dir_path):
            shutil.rmtree(dest_dir_path)
        shutil.copytree(src_dir_path, dest_dir_path)
        print(f"  Copied directory {dir_to_copy}")
    else:
        print(f"  WARNING: Source directory {src_dir_path} not found!")

    # Modify forwarder.py
    fw_path = os.path.join(dest_dir, "forwarder.py")
    if os.path.exists(fw_path):
        with open(fw_path, "r") as f:
            content = f.read()
        
        # Replace interfaces
        # The original file uses "tap0" and "tap1" in the main function and variable assignments
        content = content.replace('if0 = "tap0"', f'if0 = "{config["a"]}"')
        content = content.replace('if1 = "tap1"', f'if1 = "{config["b"]}"')
        
        # Also replace in process_packet calls if they are hardcoded strings
        content = content.replace('"tap0"', f'"{config["a"]}"')
        content = content.replace('"tap1"', f'"{config["b"]}"')
        
        # Replace classifier port
        content = content.replace(":5000", f":{config['port']}")
        
        with open(fw_path, "w") as f:
            f.write(content)
        print(f"  Configured forwarder.py for {config['a']}/{config['b']} and port {config['port']}")

    # Modify fastclass.py
    fc_path = os.path.join(dest_dir, "fastclass.py")
    if os.path.exists(fc_path):
        with open(fc_path, "r") as f:
            content = f.read()
        
        # Replace port
        content = content.replace("port=5000", f"port={config['port']}")
        
        with open(fc_path, "w") as f:
            f.write(content)
        print(f"  Configured fastclass.py port {config['port']}")

print("Setup complete.")
