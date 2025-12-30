from getpass import getpass
import string
import math
import hashlib
import requests
from colorama import init, Fore, Style
from tabulate import tabulate

init(autoreset=True)

def load_common_passwords():
    try:
        with open("common_passwords.txt") as f:
            return {line.strip().lower() for line in f}
    except FileNotFoundError:
        return set()

COMMON_PASSWORDS = load_common_passwords()

def check_length(password):
    if len(password) < 8:
        return 0, "Too short"
    elif len(password) < 12:
        return 1, "Acceptable"
    else:
        return 2, "Strong"
        
def check_complexity(password):
    score = 0
    feedback = []
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add digits")
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Add special characters")
    return score, feedback
    
def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS
    
def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if charset_size == 0:
        return 0
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def overall_rating(entropy, is_common, breached_count):
    if is_common or breached_count > 0 or entropy < 40:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    else:
        return "Strong"

def sha1_hash(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def get_hash_prefix_suffix(password):
    full_hash = sha1_hash(password)
    return full_hash[:5], full_hash[5:]

def query_hibp(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url, timeout=5)
    if response.status_code != 200:
        raise RuntimeError("Error querying HIBP API")
    return response.text

def check_hibp(password):
    try:
        prefix, suffix = get_hash_prefix_suffix(password)
        response = query_hibp(prefix)
    except Exception:
        return -1
    for line in response.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0

def analyze_password(password):
    if not password:
        print(Fore.RED + "Password cannot be empty")
        return

    length_score, length_msg = check_length(password)
    complexity_score, complexity_feedback = check_complexity(password)
    entropy = calculate_entropy(password)
    common = is_common_password(password)
    breached_count = check_hibp(password)
    rating = overall_rating(entropy, common, breached_count)

    risk = 100
    risk -= entropy / 2        
    risk -= complexity_score * 10
    risk -= length_score * 5
    if breached_count > 0:
        risk = 100          
    risk = max(0, min(100, int(risk)))

    length_color = Fore.GREEN if length_score == 2 else Fore.YELLOW if length_score == 1 else Fore.RED
    complexity_color = Fore.GREEN if complexity_score == 4 else Fore.YELLOW if complexity_score >= 2 else Fore.RED
    entropy_color = Fore.GREEN if entropy >= 60 else Fore.YELLOW if entropy >= 40 else Fore.RED
    
    if breached_count == -1:
        breaches_color = Fore.YELLOW
        breaches_display = "N/A"
    elif breached_count == 0:
        breaches_color = Fore.GREEN
        breaches_display = "0"
    else:
        breaches_color = Fore.RED
        breaches_display = str(breached_count)

    if risk <= 30:
        risk_color = Fore.GREEN
    elif risk <= 70:
        risk_color = Fore.YELLOW
    else:
        risk_color = Fore.RED

    table = [
        [
            length_color + length_msg,
            complexity_color + f"{complexity_score}/4",
            entropy_color + f"{entropy} bits",
            breaches_color + breaches_display,
            risk_color + f"{risk}/100"
        ]
    ]
    headers = ["Length", "Complexity", "Entropy", "Breaches", "Risk Score"]

    print("\n--- Password Summary ---")
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

    print("\n--- Detailed Analysis ---")
    print("Rating:", Fore.CYAN + rating)

    if common:
        print(Fore.RED + "Password is commonly used")
    if breached_count == -1:
        print(Fore.YELLOW + "Could not check breach database (Network Error)")
    elif breached_count > 0:
        if breached_count > 100000:
            print(Fore.RED + "Extremely common breached password")
        else:
            print(Fore.RED + "Password found in breaches")
    else:
        print(Fore.GREEN + "Password not found in known breaches")

    if complexity_feedback:
        print("\nSuggestions:")
        for tip in complexity_feedback:
            print("•", tip)

def main():
    try:
        password = getpass("Enter password to analyze (input hidden): ")
        analyze_password(password)
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Operation cancelled by user.")

if __name__ == "__main__":
    main()
