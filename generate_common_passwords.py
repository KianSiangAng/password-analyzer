import requests

# URL to a common passwords list (top 10,000 passwords)
COMMON_PASSWORDS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"

def download_common_passwords():
    try:
        response = requests.get(COMMON_PASSWORDS_URL, timeout=10)
        response.raise_for_status()
        passwords = response.text.strip().split("\n")
        with open("common_passwords.txt", "w", encoding="utf-8") as f:
            for pwd in passwords:
                f.write(pwd + "\n")
        print(f"Downloaded {len(passwords)} common passwords to 'common_passwords.txt'.")
    except requests.RequestException as e:
        print(f"Error downloading passwords: {e}")

if __name__ == "__main__":
    download_common_passwords()