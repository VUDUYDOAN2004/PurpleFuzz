import os
import subprocess
import random
import time
import importlib.util
from pathlib import Path
import hashlib
import uuid
import argparse 

# Configuration
SEED_DIR = "seeds"
MUTATOR_DIR = "mutators"           # Mode 0 (default)
CUSTOM_MUTATOR_DIR = "custom_mutators" # Mode 1 (custom)
TEMP_WORKDIR = "temp_workdirs"     # Temporary directory for tagging runs by ID
INTERESTING_DIR = "interesting_finds"
HAVOC_MUTATION_STEPS = 3 

# --- Priority Flags ---
PRIO_1_BYPASS_SUCCESS = 1
PRIO_2_BYPASS_FAIL = 2
PRIO_3_DETECTED_OR_ERROR = 3

# --- Communication Files ---
QUEUE_FILE = "queue.txt"
HASH_FILE = "tested_hashes.txt"

class ProducerFuzzer:
    def __init__(self, mutator_mode):
        print(f"Initializing Producer in Mutator Mode: {mutator_mode}")
        self.mutator_mode = mutator_mode

        self.corpus_by_prio = {
            PRIO_1_BYPASS_SUCCESS: [], # List for Prio 1
            PRIO_2_BYPASS_FAIL: [],    # List for Prio 2
            PRIO_3_DETECTED_OR_ERROR: [] # List for Prio 3 (original seeds)
        }
        
        self.mutators = {
            "generic": [],
            "cmd": [],
            "powershell": []
        }
        
        # Load "memory" of tested hashes
        self.tested_hashes = set()
        if os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                self.tested_hashes = set(line.strip() for line in f)
        
        self.hash_file_handle = open(HASH_FILE, 'a') # Open file for appending
        
        # Ensure all required directories exist
        os.makedirs(INTERESTING_DIR, exist_ok=True)
        os.makedirs(MUTATOR_DIR, exist_ok=True)
        os.makedirs(CUSTOM_MUTATOR_DIR, exist_ok=True) # Custom mutators directory
        os.makedirs(SEED_DIR, exist_ok=True)
        os.makedirs(TEMP_WORKDIR, exist_ok=True) # Temporary workdir for per-run IDs

    def load_mutators(self):
        try:
            from base_mutator import BaseMutator
            print("Loaded BaseMutator from root directory.")
        except ImportError:
            print("[ERROR] 'base_mutator.py' not found.")
            print("Please move 'base_mutator.py' to the same directory as 'producer.py'.")
            exit(1)

        # Select which directory to scan based on mode
        if self.mutator_mode == 0:
            mutator_dir_path = MUTATOR_DIR
            print(f"Loading DEFAULT mutators from: {MUTATOR_DIR}...")
        else: # mode == 1
            mutator_dir_path = CUSTOM_MUTATOR_DIR
            print(f"Loading CUSTOM mutators from: {CUSTOM_MUTATOR_DIR}...")
        
        mutator_files = list(Path(mutator_dir_path).glob("*.py"))

        for py_file in mutator_files:
            if py_file.name in ["__init__.py"]: 
                continue

            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isinstance(attribute, type) and issubclass(attribute, BaseMutator) and attribute is not BaseMutator:
                        instance = attribute()
                        for tag in instance.tags:
                            if tag in self.mutators:
                                self.mutators[tag].append(instance)
                                print(f"  [+] Loaded: {py_file.stem} (Tag: {tag})")
                            else:
                                print(f"  [!] Undefined tag '{tag}' in {py_file.stem}")
            except Exception as e:
                print(f"  [!] Error loading {py_file.name}: {e}")

    def load_seeds(self):
        print(f"\nLoading seeds from directory: {SEED_DIR}")
        loaded_count = 0
        for filename in os.listdir(SEED_DIR):
            if not filename.endswith(".txt"): 
                continue
                
            try:
                tags = []
                if filename.lower().startswith("ps_"):
                    tags.append("powershell")
                elif filename.lower().startswith("cmd_"):
                    tags.append("cmd")
                else:
                    tags.append("generic")

                with open(os.path.join(SEED_DIR, filename), 'r', encoding='utf-8') as f:
                    command = f.read().strip()
                    if command:
                        
                        priority = PRIO_3_DETECTED_OR_ERROR 
                        if "_fuzzed_prio_1" in filename:
                            priority = PRIO_1_BYPASS_SUCCESS
                        elif "_fuzzed_prio_2" in filename:
                            priority = PRIO_2_BYPASS_FAIL

                        self.corpus_by_prio[priority].append({
                            "cmd": command,
                            "tags": tags
                        })
                        loaded_count += 1
            except Exception as e:
                print(f"  [!] Error reading file {filename}: {e}")
        
        if loaded_count == 0:
            print("[ERROR] No seeds found. Please add .txt files to the 'seeds' directory.")
            exit(1)
        print(f"Loaded {loaded_count} seeds into priority bins.")

    def choose_seed(self):
        """
        Chooses a seed by:
        1. Selecting a priority level (Prio 1, 2, 3) based on weights.
        2. Randomly choosing a seed FROM that level.
        """
        priority_levels = [PRIO_1_BYPASS_SUCCESS, PRIO_2_BYPASS_FAIL, PRIO_3_DETECTED_OR_ERROR]
        priority_weights = [0.60, 0.30, 0.10]
        
        available_levels = []
        available_weights = []
        
        for i in range(len(priority_levels)):
            prio = priority_levels[i]
            if self.corpus_by_prio[prio]: # Check if the list is not empty
                available_levels.append(prio)
                available_weights.append(priority_weights[i])

        if not available_levels:
            # This can happen if only Prio 1/2 exist and they get depleted
            # Fallback to Prio 3
            if self.corpus_by_prio[PRIO_3_DETECTED_OR_ERROR]:
                available_levels = [PRIO_3_DETECTED_OR_ERROR]
                available_weights = [1.0]
            else:
                print("[ERROR] All seed bins are empty. Stopping.")
                exit(1)
            
        chosen_priority = random.choices(available_levels, weights=available_weights, k=1)[0]
        chosen_seed_data = random.choice(self.corpus_by_prio[chosen_priority])
        
        return chosen_seed_data 

    def apply_havoc_mutations(self, command, command_tags):
        num_steps = random.randint(1, HAVOC_MUTATION_STEPS)
        mutated_command = command
        
        valid_mutators = list(self.mutators["generic"])
        for tag in command_tags:
            if tag in self.mutators:
                valid_mutators.extend(self.mutators[tag])
        
        if not valid_mutators:
            return mutated_command

        for _ in range(num_steps):
            selected_mutator = random.choice(valid_mutators)
            try:
                mutated_command = selected_mutator.mutate(mutated_command)
            except Exception as e:
                print(f"[ERROR] Mutator {selected_mutator.__class__.__name__} failed: {e}")
                return mutated_command
                
        return mutated_command

    def execute_command(self, command_string, cwd=None):
        """
        Executes a command in a specified directory (cwd).
        """
        print(f"  [>] Executing (in dir {cwd}): {command_string[:100]}...")
        try:
            result = subprocess.run(
                command_string, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10,
                encoding='utf-8',
                cwd=cwd 
            )
            if result.returncode != 0:
                print(f"  [-] Command failed (Error: {result.stderr[:100]}...)")
            return result.returncode == 0
        except Exception as e:
            print(f"  [-] Execution error: {e}")
            return False

    def main_loop(self):
        self.load_mutators()
        self.load_seeds()

        if not self.mutators["generic"] and not self.mutators["cmd"] and not self.mutators["powershell"]:
            print("[ERROR] No mutators found in selected directory.")
            return

        print(f"\n--- START ---")

        while True:
            seed_data = self.choose_seed()
            original_command = seed_data["cmd"]
            command_tags = seed_data["tags"]
            
            mutated_command = self.apply_havoc_mutations(original_command, command_tags)
            
            if mutated_command == original_command:
                continue

            # --- Deduplication ---
            cmd_hash = hashlib.sha256(mutated_command.encode()).hexdigest()
            if cmd_hash in self.tested_hashes:
                continue 
            
            self.tested_hashes.add(cmd_hash)
            self.hash_file_handle.write(f"{cmd_hash}\n") # Write to file
            self.hash_file_handle.flush()
            
            correlation_id = str(uuid.uuid4())
            
            # Create temporary directory named by correlation ID
            temp_dir_path = os.path.join(os.getcwd(), TEMP_WORKDIR, correlation_id)
            try:
                os.makedirs(temp_dir_path, exist_ok=True)
            except Exception as e:
                print(f"[ERROR] Could not create temp dir: {e}")
                continue 

            # --- Execute and enqueue ---
            run_success = self.execute_command(mutated_command, cwd=temp_dir_path)
            
            # Clean up the temporary directory
            try:
                os.rmdir(temp_dir_path)
            except Exception as e:
                print(f"[WARN] Could not remove temp dir: {e}")
            # ------------------------------------
                
            # write to queue.txt 
            # Format: ID|RunSuccess|Tags|Command
            tags_str = " ".join(command_tags)
            with open(QUEUE_FILE, 'a', encoding='utf-8') as qf:
                # Write the 'mutated_command' (the actual command) so the consumer can record it
                qf.write(f"{correlation_id}|{run_success}|{tags_str}|{mutated_command}\n")
            
            print(f"  [+] Executed & queued (ID: ...{correlation_id[-6:]})")
            
            
if __name__ == "__main__":
    # --- Logic Argparse ---
    parser = argparse.ArgumentParser(description="PurpleFuzz - Detection-Guided Fuzzer (Producer)")
    parser.add_argument(
        "-m", "--mode",
        type=int,
        default=0,
        choices=[0, 1],
        help="Mutator mode: 0=default ('mutators' dir), 1=custom ('custom_mutators' dir)"
    )
    args = parser.parse_args()
    # ---------------------------------

    fuzzer = None # Initialize as None
    try:
        fuzzer = ProducerFuzzer(mutator_mode=args.mode) # pass mode into constructor
        fuzzer.main_loop()
    except KeyboardInterrupt:
        print("\n[!] Producer is stopping...")
    finally:
        # Ensure the hash file is always closed, even on error
        if fuzzer and fuzzer.hash_file_handle:
            fuzzer.hash_file_handle.close()
            print("[i] Hash file closed.")