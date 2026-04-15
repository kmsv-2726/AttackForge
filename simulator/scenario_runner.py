import argparse
import os
import sys
from datetime import datetime

# Make sure we can import from simulator package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.log_generator import generate_normal_logs
from simulator.attacks import phishing, ransomware, insider_threat

def main():
    parser = argparse.ArgumentParser(description="AI Cyber Attack Simulator - Scenario Runner")
    parser.add_argument('--attack', type=str, required=True, choices=['phishing', 'ransomware', 'insider_threat', 'all'],
                        help="Attack type to inject into the logs.")
    args = parser.parse_args()
    
    print("Step 1: Generating fresh normal logs...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join('data', 'normal_logs', f'normal_logs_{timestamp}.csv')
    
    # Randomize background traffic volume (2k to 10k events)
    import random
    num_normal = random.randint(2000, 10000)
    print(f"  Target volume: {num_normal} normal events")
    generate_normal_logs(out_file, num_events=num_normal)
    
    print("\nStep 2: Injecting attacks...")
    # Randomly pick an intensity for this run: stealthy, balanced, or aggressive
    intensity = random.choice([0.5, 1.0, 1.5, 2.0])
    print(f"  Simulation Intensity: {intensity}x")

    attacks_to_run = []
    if args.attack == 'all':
        attacks_to_run = [phishing, ransomware, insider_threat]
    elif args.attack == 'phishing':
        attacks_to_run = [phishing]
    elif args.attack == 'ransomware':
        attacks_to_run = [ransomware]
    elif args.attack == 'insider_threat':
        attacks_to_run = [insider_threat]
        
    for attack_module in attacks_to_run:
        print(f"\nRunning {attack_module.__name__} injection...")
        # We'll pass the intensity to the main function if supported
        try:
            attack_module.main(intensity=intensity)
        except TypeError:
            # Fallback if module main hasn't been updated yet
            attack_module.main()
        
    print("\n[DONE] Scenario extraction and injection complete.")

if __name__ == "__main__":
    main()
