# --- SIEM Configuration ---
SIEM_HOST = 'localhost'       
SIEM_PORT = 9200
SIEM_USER = 'elastic'
SIEM_PASS = '_L-LLMOjg1BKYRPxNc7h'             
SIEM_INDEX = '.internal.alerts-security.alerts-default-*'

# Protocol Configuration
SIEM_USE_SSL = True          
SIEM_VERIFY_CERTS = False     

# --- Fuzzer Configuration ---
CONSUMER_SLEEP_TIME = 90