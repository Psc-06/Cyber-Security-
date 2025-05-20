import re
import math
from difflib import SequenceMatcher

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "football", "111111", "12345678", "password1", "123123"
}

def calculate_entropy(password):
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
        charset_size += 32 

    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return entropy

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

def similar_to_common_password(password):
    for common in COMMON_PASSWORDS:
        if SequenceMatcher(None, password.lower(), common).ratio() > 0.8:
            return True
    return False

def password_strength(password):
    score = 0
    feedback = []

    if len(password) < 6:
        feedback.append("Password is too short (minimum 6 characters).")
    elif len(password) >= 12:
        score += 2
        feedback.append("Good length.")
    else:
        score += 1
        feedback.append("Password length is moderate.")

    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password))

    variety = sum([has_upper, has_lower, has_digit, has_symbol])
    score += variety

    if variety < 3:
        feedback.append("Use a mix of upper, lower, digits, and symbols.")
    else:
        feedback.append("Good character variety.")

    if is_common_password(password):
        feedback.append("This is a common password — change it!")
        score = 0
    elif similar_to_common_password(password):
        feedback.append("Password is too similar to a common password.")

    entropy = calculate_entropy(password)
    if entropy < 40:
        feedback.append(f"Password entropy is low ({entropy:.1f} bits).")
    elif entropy >= 60:
        score += 1
        feedback.append(f"Strong entropy ({entropy:.1f} bits).")

    score = min(score, 5)
    strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]

    return {
        "password": password,
        "score": score,
        "strength": strength_levels[score],
        "feedback": feedback
    }

if __name__ == "__main__":
    user_input = input("Enter a password to test: ")
    result = password_strength(user_input)

    print(f"\nPassword Strength: {result['strength']}")
    for tip in result['feedback']:
        print(f"- {tip}")
