
import zxcvbn
from zxcvbn import zxcvbn
import argparse

def analyze_password(password):
    result = zxcvbn(password)
    print(f"Password: {password}")
    print(f"Score (0-4): {result['score']}")
    print(f"Crack Time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
    print("Feedback:", result['feedback'])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("password", type=str, help="Password to analyze")
    args = parser.parse_args()
    analyze_password(args.password)
