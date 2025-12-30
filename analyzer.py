import re

def check_password(password):
    # Criteria definitions
    criteria = {
        "Length (12+)": len(password) >= 12,
        "Uppercase": re.search(r"[A-Z]", password) is not None,
        "Lowercase": re.search(r"[a-z]", password) is not None,
        "Numbers": re.search(r"\d", password) is not None,
        "Special Character": re.search(r"[!@#$%^&*]", password) is not None
    }
    
    # Calculate score (0 to 5)
    score = sum(criteria.values())
    
    if score == 5:
        result = "Very Strong"
    elif score >= 3:
        result = "Moderate"
    else:
        result = "Weak"
        
    return result, criteria

def main():
    print("--- Password Security Analyzer ---")
    pwd = input("Enter password to analyze: ")
    strength, details = check_password(pwd)
    
    print(f"\nStrength Rating: {strength}")
    for feature, met in details.items():
        icon = "✅" if met else "❌"
        print(f"{icon} {feature}")

if __name__ == "__main__":
    main()