import random
import requests
import json
import os
import datetime
import time
import traceback
from pprint import pformat
import coverage

class DjangoEndpointFuzzer:
    def __init__(self, input_file='input.json', application='Django'):
        self.seed_queue = []
        self.failure_queue = []
        self.create_output_dir()
        self.failure_types = {}  # Track types of failures
        self.request_counter = 0
        self.success_counter = 0
        self.error_counter = 0

        # For Django:
        if application == 'Django':
            self.base_url = 'http://127.0.0.1:8000/datatb/product/'
            self.endpoint_url = 'add/'
            self.url = self.base_url + self.endpoint_url
            self.headers = {
                'Content-Type': 'application/json',
                'Cookie': 'csrftoken=VALID_CSRF_TOKEN; sessionid=VALID_SESSION_ID',
            }
            self.load_seeds(input_file)

    # Load the seed input from the input file to the seed queue:
    def load_seeds(self, input_file):
        try:
            with open(input_file, 'r') as f:
                seeds = json.load(f)
                self.seed_queue.extend(seeds)
                print(f"Loaded {len(seeds)} seeds from {input_file}")
        except Exception as e:
            print(f"Error loading seeds: {e}")
            # Create at least one basic seed if loading fails
            default_seeds = [
                {
                    "name": "Default Product",
                    "price": 99.99,
                    "info": "Default product information"
                },
                {
                    "name": "Test Item",
                    "price": 100,
                    "info": "Sample description"
                }
            ]
            self.seed_queue.extend(default_seeds)
            print(f"Using {len(default_seeds)} default seeds instead")

    # To ensure that the inputs are sent in the correct json format:
    def safe_json_serialize(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, float) and (obj != obj):  # NaN check
            return "NaN"
        if obj is None:
            return None  # Keep None as None, don't convert to string
        if isinstance(obj, (dict, list, int, float, bool)):
            return obj  # Keep native JSON types as they are
        return str(obj)  # Convert everything else to string

    # ChooseNext():
    def chooseNext(self):
        if not self.seed_queue:
            # If seed queue is empty, add a basic template
            default_seed = {
                "name": f"Replenished Product {random.randint(1000, 9999)}",
                "price": round(random.uniform(10, 1000), 2),
                "info": f"Replenished product information {datetime.datetime.now()}"
            }
            self.seed_queue.append(default_seed)
            print(f"Seed queue replenished with: {default_seed}")
        return self.seed_queue.pop(0)

    # Assign energy:
    def assign_energy(self):
        return 10  # Constant value for now

    # Mutate input():
    def mutate_input(self, test_input):
        mutated = test_input.copy()
        
        #Track what mutation was applied for debugging
        mutation_type = random.choice([
            'flip_char', 
            'remove_field', 
            'invalid_type', 
            'boundary_value', 
            'division_by_zero', 
            'malformed_json',
            # 'sql_injection',
            # 'xss_attempt',
            'empty_value',
            'extremely_long_value'
        ])

        # mutation_type = 'regex'
        
        # Record the mutation type for analysis
        mutated['_mutation_type'] = mutation_type

        if mutation_type == 'flip_char' and 'name' in mutated:
            chars = list(mutated['name'])
            if chars:
                pos = random.randint(0, len(chars) - 1)
                chars[pos] = random.choice('!@#$%^&*()_+-=[]{}|;:,.<>?')  # Flip a character
                mutated['name'] = ''.join(chars)
        
        elif mutation_type == 'remove_field':
            field = random.choice(['name', 'info', 'price'])
            mutated.pop(field, None)
        
        elif mutation_type == 'invalid_type':
            field = random.choice(['name', 'info', 'price'])
            invalid_values = [None, [], {}, True, "".encode('utf-8'), set([1, 2, 3]), (1, 2, 3)]
            mutated[field] = random.choice(invalid_values)
        
        elif mutation_type == 'boundary_value' and 'price' in mutated:
            mutated['price'] = random.choice([
                -1,          # Negative price
                2**31-1,     # Large number
                "💰💰💰",     # Unexpected data type
                float('nan'),# Not a number
                0.000001,    # Very small number
                float('inf'),# Infinity
            ])

        elif mutation_type == 'division_by_zero':
            # Introducing a division by zero case
            mutated['divide_by'] = 0
        
        elif mutation_type == 'malformed_json':
            # For malformed JSON testing, we'll keep a valid structure but with strange values
            mutated = {
                "name": "TestItem", 
                "price": 100,
                "info": "Sample", 
                "extra_field": "Something extra,}",
                "_mutation_type": mutation_type
            }
        
        # elif mutation_type == 'sql_injection':
        #     field = random.choice(['name', 'info'])
        #     sql_payloads = [
        #         "'; DROP TABLE products; --",
        #         "' OR '1'='1",
        #         "'); INSERT INTO products VALUES ('hacked',0,'owned'); --",
        #         "' UNION SELECT username, password FROM users; --"
        #     ]
        #     mutated[field] = random.choice(sql_payloads)
            
        # elif mutation_type == 'xss_attempt':
        #     field = random.choice(['name', 'info'])
        #     xss_payloads = [
        #         "<script>alert('XSS')</script>",
        #         "javascript:alert('XSS')",
        #         "<img src='x' onerror='alert(1)'>",
        #         "<body onload='alert(\"XSS\")'>",
        #     ]
        #     mutated[field] = random.choice(xss_payloads)
            
        elif mutation_type == 'empty_value':
            field = random.choice(['name', 'info', 'price'])
            mutated[field] = ""
            
        elif mutation_type == 'extremely_long_value':
            # field = random.choice(['name', 'info', 'price'])
            # if field == 'name' or field == 'info':
            #     mutated[field] = "X" * (3 * 1024 * 1024)
            # elif field == 'price':
            #     mutated[field] = 10 ** 200
            mutated['price'] = 10 ** 200
            # mutated['price'] = "X" * (3 * 1024 * 1024)
            # No memory error with 2 * 1024 * 1024 = 2MB bytes (Django max size around 2.5MB)
            # mutated['name'] = "X" * (2 * 1024 * 1024)

        elif mutation_type == 'regex':
    
            mutated['name'] = "a"*100000 + "b"


        return mutated

    # Send the mutated inputs to the application:
    def execute_test(self, test_input):
        self.request_counter += 1
        request_id = self.request_counter
        
        try:
            # Remove the mutation tracking field before sending
            send_input = test_input.copy()
            mutation_type = send_input.pop('_mutation_type', 'unknown')
            
            # First, properly serialize the input for JSON
            serializable_input = {k: self.safe_json_serialize(v) for k, v in send_input.items()}
            
            # Debug log of the actual data being sent
            print(f"\n=== REQUEST #{request_id} ({mutation_type}) ===")
            print(f"URL: {self.url}")
            print(f"Data: {json.dumps(serializable_input, default=str)}")
            
            # Make the actual request
            start_time = time.time()
            response = requests.post(
                self.url, 
                headers=self.headers, 
                json=serializable_input,  # This will handle proper JSON serialization
                timeout=10   # Timeout for crash detection
            )
            elapsed = time.time() - start_time
            
            # Log the complete response
            print(f"=== RESPONSE #{request_id} ===")
            print(f"Status: {response.status_code}")
            print(f"Time: {elapsed:.2f}s")
            print(f"Headers: {dict(response.headers)}")
            print(f"Content: {response.text[:200]}")
            if len(response.text) > 200:
                print("...")
                
            # Check for error responses
            if response.status_code >= 400:
                self.error_counter += 1
                print(f"⚠️ ERROR DETECTED: Status {response.status_code}")

                if "<html" in response.text.lower():
                    if "request body exceeded" in response.text.lower():
                        simplified_error_message = "Memory error: request data too large"
                    else:
                        simplified_error_message = "Error response in HTML format - details omitted"
                else:
                    simplified_error_message = response.text

                
                # Add to failure queue directly in execute_test
                failure_record = {
                    'input': serializable_input,
                    'status_code': response.status_code,
                    'response': simplified_error_message,
                    'mutation_type': mutation_type,
                    'request_id': request_id,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.failure_queue.append(failure_record)
                
                # Track failures by type
                if mutation_type not in self.failure_types:
                    self.failure_types[mutation_type] = 0
                self.failure_types[mutation_type] += 1
                
                print(f"Added to failure queue: {mutation_type} ({response.status_code})")
            else:
                self.success_counter += 1
                
            return {
                'response': response,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': elapsed,
                'serialized_input': serializable_input
            }
        
        except requests.exceptions.Timeout as e:
            print(f"⏰ REQUEST TIMEOUT: No response in time for request #{request_id}")
            print(traceback.format_exc())

            failure_record = {
                'input': {k: str(v) for k, v in send_input.items()},
                'status_code': 'timeout',
                'response': 'No response - timeout occurred',
                'mutation_type': mutation_type,
                'request_id': request_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e)
            }

            self.failure_queue.append(failure_record)
            self.error_counter += 1

            print(f"Added to failure queue: Timeout - {mutation_type}")
            return {
                'response': None,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': 10,  # assume full timeout used
                'error': 'timeout',
                'serialized_input': {k: str(v) for k, v in send_input.items()}
            }

            
        except Exception as e:
            print(f"⚠️ REQUEST FAILED: {str(e)}")
            print(traceback.format_exc())
            
            # Add exception failures to the queue as well
            failure_record = {
                'input': {k: str(v) for k, v in send_input.items()},
                'status_code': 'exception',
                'response': str(e),
                'mutation_type': mutation_type,
                'request_id': request_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e)
            }
            
            self.failure_queue.append(failure_record)
            self.error_counter += 1
            
            print(f"Added to failure queue: Exception - {mutation_type}")
            
            return {
                'response': None,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': 0,
                'error': str(e),
                'serialized_input': {k: str(v) for k, v in send_input.items()}
            }


    def fuzz(self, max_iterations=10):
        energy = self.assign_energy()
        iteration = 0
        
        print(f"\n{'=' * 60}")
        print(f"STARTING FUZZING SESSION: {datetime.datetime.now()}")
        print(f"Base URL: {self.url}")
        print(f"Max iterations: {max_iterations}")
        print(f"Energy per input: {energy}")
        print(f"{'=' * 60}\n")
        
        try:
            while iteration < max_iterations and (self.seed_queue or iteration == 0):
                test_input = self.chooseNext()
                
                print(f"\n--- Iteration {iteration+1}/{max_iterations} ---")
                print(f"Seed input: {json.dumps(test_input, default=str)}")
                
                for energy_level in range(energy):
                    try:
                        mutated_input = self.mutate_input(test_input)
                        result = self.execute_test(mutated_input)
                        
                        if not result.get('response'):
                            print(f"Request failed: {result.get('error', 'Unknown error')}")
                            continue
                            
                        # Short pause to avoid overwhelming the server
                        time.sleep(0.2)

                        if self.is_interesting(result.get('response'), mutated_input):
                            self.seed_queue.append(mutated_input)
                            print(f"Found interesting input: {json.dumps(mutated_input, indent=2)}")
                    
                    except Exception as e:
                        print(f"Error during fuzzing: {e}")
                        print(traceback.format_exc())
                        
                iteration += 1
                
                # Save failures incrementally to avoid losing data
                if len(self.failure_queue) % 5 == 0 and self.failure_queue:
                    print("Saving failures incrementally...")
                    self.save_failures()

        
        except KeyboardInterrupt:
            print("\nFuzzing interrupted by user. Saving results...")
        
        finally:
            # Print summary at the end
            print("\n" + "=" * 60)
            print(f"FUZZING SESSION COMPLETE: {datetime.datetime.now()}")
            print(f"Total requests: {self.request_counter}")
            print(f"Successful responses: {self.success_counter}")
            print(f"Error responses: {self.error_counter}")
            print(f"Failures collected: {len(self.failure_queue)}")
            
            # Print failure types summary
            if self.failure_types:
                print("\nFailure types summary:")
                for mutation_type, count in self.failure_types.items():
                    print(f"  {mutation_type}: {count} failures")
            
            # Save all failures to files
            self.save_failures()
            
            return self.failure_queue

    def save_failures(self):
        if self.failure_queue:
            print(f"\nSaving {len(self.failure_queue)} failures to file.")
            
            # Save all failures to the main failure file
            with open(self.failure_file, 'w') as f:
                json.dump(self.failure_queue, f, indent=2, default=str)
            
            # Also save categorized failures by mutation type
            by_type_dir = os.path.join(self.output_dir, "by_type")
            os.makedirs(by_type_dir, exist_ok=True)
            
            failures_by_type = {}
            for failure in self.failure_queue:
                mutation_type = failure.get('mutation_type', 'unknown')
                if mutation_type not in failures_by_type:
                    failures_by_type[mutation_type] = []
                failures_by_type[mutation_type].append(failure)
            
            for mutation_type, failures in failures_by_type.items():
                type_file = os.path.join(by_type_dir, f"{mutation_type}_failures.json")
                with open(type_file, 'w') as f:
                    json.dump(failures, f, indent=2, default=str)
            
            # Generate a summary report
            summary_file = os.path.join(self.output_dir, "summary.txt")
            with open(summary_file, 'w') as f:
                f.write(f"Fuzzing Summary Report\n")
                f.write(f"======================\n")
                f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Total Requests: {self.request_counter}\n")
                f.write(f"Successful Responses: {self.success_counter}\n")
                f.write(f"Error Responses: {self.error_counter}\n")
                f.write(f"Failures Collected: {len(self.failure_queue)}\n\n")
                
                f.write("Failures by type:\n")
                for mutation_type, count in self.failure_types.items():
                    f.write(f"  {mutation_type}: {count} failures\n")
                
                f.write("\nStatus Code Distribution:\n")
                status_counts = {}
                for failure in self.failure_queue:
                    status = str(failure.get('status_code', 'unknown'))
                    if status not in status_counts:
                        status_counts[status] = 0
                    status_counts[status] += 1
                
                for status, count in sorted(status_counts.items(), key=lambda x: str(x[0])):
                    f.write(f"  {status}: {count} occurrences\n")
                
                # Include most common failure patterns
                if self.failure_queue:
                    f.write("\nSample Failures:\n")
                    for i, failure in enumerate(self.failure_queue[:5]):
                        f.write(f"\n--- Failure #{i+1} ---\n")
                        f.write(f"Mutation: {failure.get('mutation_type')}\n")
                        f.write(f"Status: {failure.get('status_code')}\n")
                        f.write(f"Input: {json.dumps(failure.get('input'), indent=2)}\n")
                        response_text = failure.get('response', '')
                        if len(response_text) > 200:
                            response_text = response_text[:200] + "..."
                        f.write(f"Response: {response_text}\n")
            
            print(f"Failures saved in {self.failure_file}")
            print(f"Summary report saved in {summary_file}")
        else:
            print("No failures to save.")

    # Create the output dir to store the failure test cases for reproducibility:
    def create_output_dir(self):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"fuzzing_results_{timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.failure_file = os.path.join(self.output_dir, "failures.json")
        
        print(f"Results will be saved to: {self.output_dir}")