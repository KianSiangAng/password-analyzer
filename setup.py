import os
import subprocess
import sys

def install_dependencies():
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def generate_common_passwords():
    print("Generating common_passwords.txt...")
    subprocess.check_call([sys.executable, "generate_common_passwords.py"])

if __name__ == "__main__":
    install_dependencies()
    generate_common_passwords()
    print("\nSetup complete! You can now run 'python analyzer.py'")