import os
import subprocess
import random
import time
import importlib.util
from pathlib import Path
import hashlib
import uuid

# Configuration
SEED_DIR = "seeds"
MUTATOR_DIR = "mutators"
INTERESTING_DIR = "interesting_finds"
HAVOC_MUTATION_STEPS = 3 

# Priority Flags
PRIO_1_BYPASS_SUCCESS = 1
PRIO_2_BYPASS_FAIL = 2
PRIO_3_DETECTED_OR_ERROR = 3

# Communication Files
QUEUE_FILE = "queue.txt"
HASH_FILE = "tested_hashes.txt"

class ProducerFuzzer:
    def __init__(self):
        # self.corpus stores seeds: [{"cmd": str, "priority": int, "tags": list}, ...]
        self.corpus = []
        
        # self.mutators are organized by tags
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
        
        os.makedirs(INTERESTING_DIR, exist_ok=True)
        os.makedirs(MUTATOR_DIR, exist_ok=True)
        os.makedirs(SEED_DIR, exist_ok=True)

    def load_mutators(self):
        print("Loading mutators...")
        from mutators.base_mutator import BaseMutator

        mutator_files = list(Path(MUTATOR_DIR).glob("*.py"))

        for py_file in mutator_files:
            if py_file.name in ["base_mutator.py", "__init__.py"]:
                continue

            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isinstance(attribute, type) and issubclass(attribute, BaseMutator) and attribute is not BaseMutator:
                        instance = attribute()
                        # Add instance to the correct list based on tags
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
        for filename in os.listdir(SEED_DIR):
            try:
                # Determine tags from filename
                tags = []
                if filename.lower().startswith("ps_"):
                    tags.append("powershell")
                elif filename.lower().startswith("cmd_"):
                    tags.append("cmd")
                else:
                    tags.append("generic") # Default if no prefix

                with open(os.path.join(SEED_DIR, filename), 'r', encoding='utf-8') as f:
                    command = f.read().strip()
                    if command:
                        self.corpus.append({
                            "cmd": command,
                            "priority": PRIO_1_BYPASS_SUCCESS,
                            "tags": tags
                        })
            except Exception as e:
                print(f"  [!] Error reading file {filename}: {e}")
        
        if not self.corpus:
            print("[ERROR] No seeds found. Please add .txt files to the 'seeds' directory.")
            exit(1)
        print(f"Loaded {len(self.corpus)} seeds.")

    def choose_seed(self):
        weights = [1.0 / s["priority"] for s in self.corpus]
        chosen_seed_data = random.choices(self.corpus, weights=weights, k=1)[0]
        return chosen_seed_data # return all dict (cmd, priority, tags)

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

    def execute_command(self, command_string):
        print(f"  [>] Executing: {command_string[:100]}...") # Truncate long commands
        try:
            result = subprocess.run(
                command_string, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10,
                encoding='utf-8'
            )
            return result.returncode == 0
        except Exception:
            return False

    def main_loop(self):
        self.load_mutators()
        self.load_seeds()

        if not self.mutators["generic"] and not self.mutators["cmd"] and not self.mutators["powershell"]:
            print("[ERROR] No mutators found")
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
            
            # --- CREATE CORRELATION ID AND EMBED INTO COMMAND ---
            correlation_id = str(uuid.uuid4())
            tagged_command = ""
            
            if "powershell" in command_tags:
                tagged_command = f"{mutated_command}; Write-Output '{correlation_id}'"
            else:
                tagged_command = f"{mutated_command} & echo {correlation_id}"
                
            # --- Execute and enqueue ---
            run_success = self.execute_command(tagged_command)
            
            # write to queue.txt 
            # Format: ID|RunSuccess|Tags|Command
            tags_str = " ".join(command_tags)
            with open(QUEUE_FILE, 'a', encoding='utf-8') as qf:
                qf.write(f"{correlation_id}|{run_success}|{tags_str}|{mutated_command}\n")
            
            print(f"  [+] Executed & queued (ID: ...{correlation_id[-6:]})")
            
            

if __name__ == "__main__":
    try:
        fuzzer = ProducerFuzzer()
        fuzzer.main_loop()
    except KeyboardInterrupt:
        print("\n[!] Producer is stopping...")
        fuzzer.hash_file_handle.close()