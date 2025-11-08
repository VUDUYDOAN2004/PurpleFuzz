import time
import os
import config 
from elasticsearch import Elasticsearch, exceptions

#Configuration
QUEUE_FILE = "queue.txt"
INTERESTING_DIR = "interesting_finds"
SEED_DIR = "seeds" 

#Set Priority
PRIO_1_BYPASS_SUCCESS = 1
PRIO_2_BYPASS_FAIL = 2
PRIO_3_DETECTED_OR_ERROR = 3

class ConsumerSIEM:
    def __init__(self):
        print("Đang khởi tạo Consumer...")
        os.makedirs(INTERESTING_DIR, exist_ok=True)
        os.makedirs(SEED_DIR, exist_ok=True) 
        
        print(f"Đang kết nối đến SIEM tại {config.SIEM_HOST}...")
        try:
            # Check if pass and user are available in the configuration
            http_auth = None
            if config.SIEM_USER and config.SIEM_PASS:
                http_auth = (config.SIEM_USER, config.SIEM_PASS)

            # Decide to use http or https protocol
            scheme = "https" if config.SIEM_USE_SSL else "http"

            self.siem_client = Elasticsearch(
                hosts=[
                    {
                        'host': config.SIEM_HOST, 
                        'port': config.SIEM_PORT, 
                        'scheme': scheme
                    }
                ],
                http_auth=http_auth,
                verify_certs=config.SIEM_VERIFY_CERTS
            )
            

            if not self.siem_client.ping():
                raise Exception("Ping failed")
            print("[+] Kết nối SIEM thành công.")
        except Exception as e:
            print(f"[LỖI] Không thể kết nối đến Elasticsearch: {e}")
            exit(1)

    def query_siem_for_ids(self, correlation_ids):
        
        if not correlation_ids:
            return set()

        print(f"  [?] Đang truy vấn SIEM cho {len(correlation_ids)} IDs...")
        
        query_body = {
            "query": {
                "terms": {
                    "message": correlation_ids 
                }
            },
            "_source": ["message"], # Take the message field only
            "size": len(correlation_ids) # Take N results at most
        }
        
        try:
            response = self.siem_client.search(
                index=config.SIEM_INDEX,
                body=query_body
            )
            
            detected_ids = set()
            for hit in response['hits']['hits']:
                log_message = hit['_source'].get('message', '')
                for cid in correlation_ids:
                    if cid in log_message:
                        detected_ids.add(cid)
            
            print(f"  [!] SIEM đã phát hiện {len(detected_ids)} IDs.")
            return detected_ids

        except exceptions.NotFoundError:
            print(f"  [LỖI] Index '{config.SIEM_INDEX}' không tồn tại.")
            return set()
        except Exception as e:
            print(f"  [LỖI] Truy vấn SIEM thất bại: {e}")
            return set()

    def process_queue(self):
        """
        Xử lý file queue, gán cờ, và lưu kết quả.
        """
        processing_file = "queue.processing.txt"
        try:
            # Change the filename to avoid override
            os.rename(QUEUE_FILE, processing_file)
        except FileNotFoundError:
            print("  [~] Không có file queue nào để xử lý.")
            return

        # Dict: {id: {"success": bool, "cmd": str, "tags": list}}
        commands_to_check = {} 
        with open(processing_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    # Format: ID|RunSuccess|Tags|Command
                    cid, success_str, tags_str, cmd = line.strip().split('|', 3)
                    commands_to_check[cid] = {
                        "success": (success_str == 'True'),
                        "cmd": cmd,
                        "tags": tags_str.split(' ')
                    }
                except ValueError:
                    continue
        
        os.remove(processing_file) 
        
        if not commands_to_check:
            return

        # SIEM query
        all_ids = list(commands_to_check.keys())
        detected_ids = self.query_siem_for_ids(all_ids)

        # Flag and save the results
        for cid, data in commands_to_check.items():
            was_detected = cid in detected_ids
            run_success = data["success"]
            command = data["cmd"]
            tags = data["tags"]
            
            priority = PRIO_3_DETECTED_OR_ERROR

            if not was_detected and run_success:
                # Successful bypass and valid requests
                priority = PRIO_1_BYPASS_SUCCESS
            elif not was_detected and not run_success:
                # Valid but not successful
                priority = PRIO_2_BYPASS_FAIL

            # Interesting path --> priority 1 and 2
            if priority <= PRIO_2_BYPASS_FAIL:
                filename = f"prio_{priority}__{int(time.time())}__{cid[:4]}.txt"
                
                # save in interesting_finds
                filepath = os.path.join(INTERESTING_DIR, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(command)
                
            
                # Add to seeds and change filename so that the producer can recognize them.
                original_tag = tags[0] if tags else "generic"
                seed_filename = f"{original_tag}_fuzzed_{filename}" 
                seed_filepath = os.path.join(SEED_DIR, seed_filename)
                with open(seed_filepath, 'w', encoding='utf-8') as f:
                    f.write(command)

                print(f"  [***] Tìm thấy Bypass Prio {priority}! Đã lưu và thêm vào seeds.")

    def main_loop(self):
        
        sleep_time = config.CONSUMER_SLEEP_TIME
        print(f"--- BẮT ĐẦU CONSUMER (Ngủ {sleep_time} giây) ---")
        while True:
            time.sleep(sleep_time)
            print(f"\n--- {time.ctime()} ---")
            print("--- Thức dậy, bắt đầu xử lý hàng đợi ---")
            self.process_queue()

if __name__ == "__main__":
    try:
        consumer = ConsumerSIEM()
        consumer.main_loop()
    except KeyboardInterrupt:
        print("\n[!] Consumer đang dừng...")