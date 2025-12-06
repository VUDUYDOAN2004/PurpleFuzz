import time
import os
import config 
import re 
import urllib3 
from elasticsearch import Elasticsearch, exceptions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
QUEUE_FILE = "queue.txt"
INTERESTING_DIR = "interesting_finds"
SEED_DIR = "seeds" 
ALERT_DIR = "alerts" 

# --- Priority Flags ---
PRIO_1_BYPASS_SUCCESS = 1
PRIO_2_BYPASS_FAIL = 2
PRIO_3_DETECTED_OR_ERROR = 3

class ConsumerSIEM:
    def __init__(self):
        print("Initializing Consumer...")
        os.makedirs(INTERESTING_DIR, exist_ok=True)
        os.makedirs(SEED_DIR, exist_ok=True)
        os.makedirs(ALERT_DIR, exist_ok=True)
        
        print(f"Connecting to SIEM at {config.SIEM_HOST}...")
        try:
            auth_creds = None
            if config.SIEM_USER and config.SIEM_PASS:
                auth_creds = (config.SIEM_USER, config.SIEM_PASS)

            scheme = "https" if config.SIEM_USE_SSL else "http"

            self.siem_client = Elasticsearch(
                hosts=[{'host': config.SIEM_HOST, 'port': config.SIEM_PORT, 'scheme': scheme}],
                basic_auth=auth_creds, 
                verify_certs=config.SIEM_VERIFY_CERTS,
                ssl_show_warn=False 
            )
            
            if not self.siem_client.ping():
                raise Exception("Ping failed")
            print("[+] SIEM connection successful.")
        except Exception as e:
            print(f"[ERROR] Could not connect to Elasticsearch: {e}")
            exit(1)

    def query_siem_for_ids(self, correlation_ids):
        if not correlation_ids:
            return set()

        print(f"  [?] Querying SIEM for {len(correlation_ids)} IDs...")
        
        batch_size = 50 
        detected_ids = set()

        # Build regex to scan IDs from results 
        try:
            id_regex = re.compile("|".join(re.escape(cid) for cid in correlation_ids))
        except re.error as e:
            print(f"  [ERROR] Regex compilation failed: {e}")
            return set()

        for i in range(0, len(correlation_ids), batch_size):
            batch_ids = correlation_ids[i:i + batch_size]
            should_clauses = []
            for cid in batch_ids:
                # Search in field containing main ID
                should_clauses.append({"match_phrase": {"winlog.event_data.CurrentDirectory": cid}})
                # Fallback search in message
                should_clauses.append({"match_phrase": {"message": cid}})

            query_body = {
                "query": {
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                },
                "_source": ["winlog.event_data.CurrentDirectory", "message"], 
                "size": 1000 
            }
            # ---------------------------

            try:
                response = self.siem_client.search(
                    index=config.SIEM_INDEX,
                    body=query_body
                )
                
                # Scan results
                for hit in response['hits']['hits']:
                    raw_text = str(hit['_source']) 
                    found = id_regex.findall(raw_text)
                    detected_ids.update(found)

            except Exception as e:
                print(f"  [ERROR] Batch query failed: {e}")
                continue

        print(f"  [!] SIEM detected {len(detected_ids)} IDs.")
        return detected_ids

    def process_queue(self):
        processing_file = "queue.processing.txt"
        try:
            os.rename(QUEUE_FILE, processing_file)
        except FileNotFoundError:
            print("  [~] No queue file to process.")
            return

        commands_to_check = {} 
        try:
            with open(processing_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        cid, success_str, tags_str, cmd = line.strip().split('|', 3)
                        commands_to_check[cid] = {
                            "success": (success_str == 'True'),
                            "cmd": cmd,
                            "tags": tags_str.split(' ')
                        }
                    except ValueError:
                        continue
            
            if not commands_to_check:
                os.remove(processing_file)
                return

            all_ids = list(commands_to_check.keys())
            detected_ids = self.query_siem_for_ids(all_ids)

            for cid, data in commands_to_check.items():
                was_detected = cid in detected_ids
                run_success = data["success"]
                command = data["cmd"]
                tags = data["tags"]
                
                priority = PRIO_3_DETECTED_OR_ERROR

                if not was_detected and run_success:
                    priority = PRIO_1_BYPASS_SUCCESS
                elif not was_detected and not run_success:
                    priority = PRIO_2_BYPASS_FAIL

                # Create common filename
                filename = f"prio_{priority}__{int(time.time())}__{cid[:4]}.txt"
                original_tag = tags[0] if tags else "generic"
                seed_filename = f"{original_tag}_fuzzed_{filename}" 
                seed_filepath = os.path.join(SEED_DIR, seed_filename)

                # PRIO 1: Save to interesting_finds AND add to seeds
                if priority == PRIO_1_BYPASS_SUCCESS:
                    filepath = os.path.join(INTERESTING_DIR, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(command)
                    
                    # Add to seeds
                    with open(seed_filepath, 'w', encoding='utf-8') as f:
                        f.write(command)

                    print(f"  [***] Found Bypass Prio 1! Saved & added to seeds.")
                
                # PRIO 2
                elif priority == PRIO_2_BYPASS_FAIL:
                    pass # Ignored

                # PRIO 3: Save alerts AND add to seeds
                elif priority == PRIO_3_DETECTED_OR_ERROR:
                    filepath = os.path.join(ALERT_DIR, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(command)
                    
                    # Add to seeds 
                    with open(seed_filepath, 'w', encoding='utf-8') as f:
                        f.write(command)
                        
                    # print(f"  [!] Detected (Prio 3). Saved & added to seeds.")

            os.remove(processing_file)
            print("  [+] Queue processing complete.")

        except Exception as e:
            print(f"[CRITICAL ERROR] Queue processing failed: {e}")
            if os.path.exists(processing_file):
                try:
                    if os.path.exists(QUEUE_FILE):
                        with open(QUEUE_FILE, 'a', encoding='utf-8') as qf:
                            with open(processing_file, 'r', encoding='utf-8') as pf:
                                qf.write(pf.read())
                        os.remove(processing_file)
                    else:
                        os.rename(processing_file, QUEUE_FILE)
                except Exception as rename_e:
                    print(f"[ERROR] Could not revert queue file: {rename_e}")

    def main_loop(self):
        sleep_time = config.CONSUMER_SLEEP_TIME
        print(f"--- STARTING CONSUMER (sleep {sleep_time} seconds) ---")
        while True:
            time.sleep(sleep_time)
            print(f"\n--- {time.ctime()} ---")
            print("--- Woke up, starting to process the queue ---")
            self.process_queue()

if __name__ == "__main__":
    try:
        consumer = ConsumerSIEM()
        consumer.main_loop()
    except KeyboardInterrupt:
        print("\n[!] Consumer is stopping...")
