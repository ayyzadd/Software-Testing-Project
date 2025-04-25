#!/usr/bin/env python3
"""
Test Driver for Unified Fuzzer
This script runs the unified fuzzer with specified configuration
"""

import asyncio
import argparse
from unified_fuzzer import UnifiedFuzzer

def parse_arguments():
    """Parse command line arguments for the test driver"""
    parser = argparse.ArgumentParser(description="Test Driver for Unified Fuzzer")
    parser.add_argument('--target', choices=['django', 'ble', 'both'], default='both',
                        help='Target to fuzz: django, ble, or both')
    parser.add_argument('--iterations', type=int, default=50,
                        help='Number of fuzzing iterations to run')
    parser.add_argument('--timeout', type=int, default=20,
                        help='Timeout in seconds for each fuzzing iteration')
    parser.add_argument('--output', type=str, default='fuzzing_results',
                        help='Directory to store fuzzing results')
    parser.add_argument('--django-url', type=str, default='http://127.0.0.1:8000/datatb/product/',
                        help='Base URL of the Django application to fuzz')
    parser.add_argument('--ble-device', type=str, default='Smart Lock [Group 2]',
                        help='BLE device name to connect to')
    
    return parser.parse_args()

async def run_fuzzer():
    """Run the unified fuzzer with configuration from arguments"""
    args = parse_arguments()
    
    # Create configuration dict
    config = {
        'target': args.target,
        'iterations': args.iterations,
        'timeout': args.timeout,
        'output_dir': args.output,
        'django_url': args.django_url,
        'ble_device': args.ble_device,
        'django_input': 'django/input.json',
        'ble_input': 'ble/Input1.json',
        'enable_coverage': True
    }
    
    print(f"Starting unified fuzzer with configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    # Create and run the unified fuzzer
    fuzzer = UnifiedFuzzer(config)
    await fuzzer.run()

def main():
    """Main entry point"""
    try:
        asyncio.run(run_fuzzer())
    except KeyboardInterrupt:
        print("\nTest driver interrupted by user")
    except Exception as e:
        print(f"\nError in test driver: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()