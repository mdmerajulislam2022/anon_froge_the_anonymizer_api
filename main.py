from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from datetime import datetime
import csv
import logging
import os
import subprocess
import pickle
from ldap3 import Server, Connection, ALL
from contextlib import asynccontextmanager
from tqdm import tqdm

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('anonymizer_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables
_thread_pool = ThreadPoolExecutor(max_workers=4)
_anonymization_log = []
_employee_data = []  # Runtime memory storage

class AnonymizeRequest(BaseModel):
    texts: List[str]

class AnonymizeResponse(BaseModel):
    anonymized_texts: List[str]



def get_secrets(secret_path, keys):
    """Get secrets from HashiCorp Vault"""
    secrets = {}
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    vault_script_path = os.path.join(curr_dir, "hcvault", "gethcvaultsecrets.py")
    print('*********************************')
    print(vault_script_path, secret_path)
    cmd = ["python", vault_script_path, secret_path] + keys
    try:
        process = subprocess.run(cmd, capture_output=True, check=True)
        if process.returncode == 0 and process.stdout:
            pickle_start = process.stdout.find(b'\x80\x04')
            if pickle_start != -1:
                pickle_data = process.stdout[pickle_start:]
                secrets = pickle.loads(pickle_data)
        return secrets
    except:
        return {}

def get_credentials():
    """Get AD credentials from vault"""
    secrets = get_secrets("home/ad_db", [])
    if not secrets or not all(key in secrets for key in ['SUPPER_USER_USERID', 'SUPPER_USER_PASSWD']):
        logger.error("Required AD secrets not found!")
        return None, None
    return secrets.get('SUPPER_USER_USERID'), secrets.get('SUPPER_USER_PASSWD')

def load_employee_data_from_ad():
    """Load employee data from AD with progress bar"""
    global _employee_data
    try:
        username, password = get_credentials()
        if not username:
            return []
        
        secrets = get_secrets("home/ad_db", [])
        server = Server(secrets.get('LDAP_SERVER'), get_info=ALL)
        user_dn = f"{username}@{secrets.get('DOMAIN')}"
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        
        employees = []
        processed_count = 0
        
        # Create progress bar
        pbar = tqdm(desc="Loading AD entries", unit="entries", dynamic_ncols=True)
        
        entry_generator = conn.extend.standard.paged_search(
            search_base=secrets.get('BASE_DN'),
            search_filter='(&(objectClass=person)(givenName=*)(sn=*))',
            attributes=['cn', 'givenName', 'sn', 'title', 'l', 'mail', 'telephoneNumber', 'sAMAccountName', 'displayName'],
            paged_size=1000,
            generator=True
        )
        
        for entry in entry_generator:
            processed_count += 1
            pbar.update(1)
            
            if 'attributes' in entry:
                attrs = entry['attributes']
                employee = [
                    str(attrs.get('sAMAccountName')).upper(),
                    str(attrs.get('cn')),
                    str(attrs.get('givenName')),
                    str(attrs.get('sn')),
                    str(attrs.get('title')),
                    str(attrs.get('l')),
                    str(attrs.get('mail')),
                    str(attrs.get('telephoneNumber')),
                    str(attrs.get('displayName', ''))
                ]
                if employee and len(employee[0]) == 7:
                    employees.append(employee)
            
            # Update progress bar description with current counts
            if processed_count % 100 == 0:
                pbar.set_description(f"Loading AD entries (Valid: {len(employees)})")
        
        pbar.close()
        conn.unbind()
        
        # Filter employees with valid data with progress bar
        print("Filtering employee data...")
        filtered_employees = [
            emp for emp in tqdm(employees, desc="Filtering employees", unit="emp")
            if emp and len(emp) >= 9 and emp[2] and emp[2].strip() and emp[2] not in ('None', 'none', '', ' ', '[]') 
            and emp[8] and emp[8].strip() and emp[8] not in ('None', 'none', '', ' ', '[]')
        ]
        
        _employee_data = filtered_employees
        logger.info(f"Loaded {len(_employee_data)} employee records into memory")
        return _employee_data
    except Exception as e:
        logger.error(f"Error loading employee data from AD: {e}")
        return []

def get_employee_data():
    """Get employee data from runtime memory"""
    return _employee_data

async def get_patterns(employees):
    """Create lookup sets for O(1) performance"""
    loop = asyncio.get_event_loop()
    
    def build_patterns():
        USERIDs, emails, phones, full_names, display_names = set(), set(), set(), set(), set()
        
        for emp in employees:
            USERID, _, first_name, last_name, _, _, email, phone, display_name = emp
            
            if USERID and len(USERID.strip()) > 6:
                USERIDs.add(USERID.strip().lower())
            if email and '@' in email:
                emails.add(email.strip().lower())
            if phone and len(phone.strip()) > 5:
                phones.add(phone.strip())
            if first_name and last_name and first_name.strip() and last_name.strip():
                f_l_name = f"{first_name.strip()} {last_name.strip()}"
                l_f_name = f"{last_name.strip()} {first_name.strip()}"
                if len(f_l_name.strip()) > 3:
                    full_names.add(f_l_name.lower())
                if len(l_f_name.strip()) > 3:
                    full_names.add(l_f_name.lower())

            if display_name and len(display_name.strip()) > 3:
                display_names.add(display_name.strip().lower())

        patterns = {
            'USERID_set': USERIDs,
            'email_set': emails, 
            'phone_set': phones,
            'full_name_set': full_names,
            'display_name_set': display_names
        }
        
        # Compiled regex for general patterns
        patterns['ip'] = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        patterns['phone_plus'] = re.compile(r'[+0][0-9\s\-\(\)]*\d{8,}[0-9\s\-\(\)]*')
        patterns['email_general'] = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        patterns['date'] = re.compile(r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{2,4})\b', re.IGNORECASE)
        

        
        return patterns
    
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(executor, build_patterns)

def log_anonymization(original_text, replacement, anonymizer_name, sequence):
    """Log anonymization action"""
    _anonymization_log.append({
        'sequence': sequence,
        'original_text': original_text,
        'replacement': replacement,
        'anonymizer': anonymizer_name,
        'timestamp': datetime.now().isoformat()
    })
    # Also log to .log file
    #logger.info(f"Anonymized: '{original_text}' -> '{replacement}' (Type: {anonymizer_name}, Seq: {sequence})")

def save_anonymization_log(filename='anonymization_log.csv'):
    """Save anonymization log to CSV and .log file"""
    if _anonymization_log:
        # Save to CSV
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['sequence', 'original_text', 'replacement', 'anonymizer', 'timestamp'])
            writer.writeheader()
            writer.writerows(_anonymization_log)
        
        # Save to .log file
        log_filename = filename.replace('.csv', '.log')
        with open(log_filename, 'w', encoding='utf-8') as f:
            f.write(f"Anonymization Log - {datetime.now().isoformat()}\n")
            f.write("=" * 50 + "\n")
            for entry in _anonymization_log:
                f.write(f"[{entry['timestamp']}] Seq:{entry['sequence']} | {entry['anonymizer']} | '{entry['original_text']}' -> '{entry['replacement']}'\n")
        
        return filename
    return None

def load_config(config_path: str = "config.json"):
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except:
        return {}

def apply_config_rules(text: str, config: dict, sequence_counter=[0]) -> str:
    """Apply custom rules from config file"""
    if not text or not config:
        return text
    
    # Apply direct replacements
    for old_text, new_text in config.get('replacements', {}).items():
        if old_text in text:
            matches = re.findall(re.escape(old_text), text, flags=re.IGNORECASE)
            for match in matches:
                sequence_counter[0] += 1
                log_anonymization(match, new_text, 'config_replacement', sequence_counter[0])
            text = re.sub(re.escape(old_text), new_text, text, flags=re.IGNORECASE)
    
    # Apply group replacements
    for replacement, words in config.get('group_replacements', {}).items():
        for word in words:           
            if word.lower() in text.lower():
                matches = re.findall(r'\b' + re.escape(word) + r'\b', text, flags=re.IGNORECASE)
                for match in matches:
                    sequence_counter[0] += 1
                    log_anonymization(match, replacement, 'config_group', sequence_counter[0])
                text = re.sub(r'\b' + re.escape(word) + r'\b', replacement, text, flags=re.IGNORECASE)
    
    # Apply regex rules
    for pattern, replacement in config.get('rules', {}).items():
        try:
            regex = re.compile(pattern)
            for match in regex.finditer(text):
                sequence_counter[0] += 1
                log_anonymization(match.group(), replacement, 'config_regex', sequence_counter[0])
            text = regex.sub(replacement, text)
        except:
            continue
    
    return text

def anonymize_text_sync(text: str, patterns: dict, sequence_counter=[0]) -> str:
    """Fast text anonymization using set lookups"""
    if not text or len(text) < 3:
        return text
    
    # Apply regex patterns for IP, phone, email, date
    if 'ip' in patterns:
        for match in patterns['ip'].finditer(text):
            sequence_counter[0] += 1
            log_anonymization(match.group(), '[[IP_ADDRESS]]', 'regex_ip', sequence_counter[0])
        text = patterns['ip'].sub('[[IP_ADDRESS]]', text)
    
    if 'phone_plus' in patterns:
        for match in patterns['phone_plus'].finditer(text):
            sequence_counter[0] += 1
            log_anonymization(match.group(), '[[PHONE_NUMBER]]', 'regex_phone', sequence_counter[0])
        text = patterns['phone_plus'].sub('[[PHONE_NUMBER]]', text)
    
    if 'email_general' in patterns:
        for match in patterns['email_general'].finditer(text):
            sequence_counter[0] += 1
            log_anonymization(match.group(), '[[EMAIL_ADDRESS]]', 'regex_email', sequence_counter[0])
        text = patterns['email_general'].sub('[[EMAIL_ADDRESS]]', text)
    
    if 'date' in patterns:
        for match in patterns['date'].finditer(text):
            sequence_counter[0] += 1
            log_anonymization(match.group(), '[[DATE]]', 'regex_date', sequence_counter[0])
        text = patterns['date'].sub('[[DATE]]', text)
    
    # Apply database patterns
    text_lower = text.lower()
    for USERID in patterns.get('USERID_set', set()):
        if USERID in text_lower:
            matches = re.findall(r'\b' + re.escape(USERID) + r'\b', text, flags=re.IGNORECASE)
            for match in matches:
                sequence_counter[0] += 1
                log_anonymization(match, '[[USERID]]', 'database_USERID', sequence_counter[0])
            text = re.sub(r'\b' + re.escape(USERID) + r'\b', '[[USERID]]', text, flags=re.IGNORECASE)
    

    
    # Apply name patterns
    for display_name in patterns.get('display_name_set', set()):
        if display_name in text_lower:
            matches = re.findall(r'\b' + re.escape(display_name) + r'\b', text, flags=re.IGNORECASE)
            for match in matches:
                sequence_counter[0] += 1
                log_anonymization(match, '[[NAME]]', 'database_display_name', sequence_counter[0])
            text = re.sub(r'\b' + re.escape(display_name) + r'\b', '[[NAME]]', text, flags=re.IGNORECASE)
    
    for full_name in patterns.get('full_name_set', set()):
        if full_name in text_lower:
            matches = re.findall(r'\b' + re.escape(full_name) + r'\b', text, flags=re.IGNORECASE)
            for match in matches:
                sequence_counter[0] += 1
                log_anonymization(match, '[[NAME]]', 'database_full_name', sequence_counter[0])
            text = re.sub(r'\b' + re.escape(full_name) + r'\b', '[[NAME]]', text, flags=re.IGNORECASE)
    
    return text

async def anonymize_strings(texts: List[str]) -> List[str]:
    """Main function to anonymize list of strings"""
    global _anonymization_log
    _anonymization_log = []  # Reset log
    
    logger.info("Loading employee data and patterns")
    # Load employee data and patterns
    loop = asyncio.get_event_loop()
    employees = await loop.run_in_executor(_thread_pool, get_employee_data)
    patterns = await get_patterns(employees)
    config = load_config()
    logger.info(f"Loaded {len(employees)} employee records and {len(config)} config rules")
    
    # Process texts
    anonymized_texts = []
    for i, text in enumerate(texts):
        logger.debug(f"Processing text {i+1}/{len(texts)}")
        # Apply database patterns first
        anonymized_text = anonymize_text_sync(text, patterns)
        # Apply config rules
        if config:
            anonymized_text = apply_config_rules(anonymized_text, config)
        anonymized_texts.append(anonymized_text)
    
    # Always save log
    save_anonymization_log(f'anonymization_log.csv')
    logger.info(f"Anonymization completed. {len(_anonymization_log)} replacements made")
    
    return anonymized_texts

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load employee data into memory on startup"""
    logger.info("Loading employee data on startup...")
    try:
        await asyncio.get_event_loop().run_in_executor(_thread_pool, load_employee_data_from_ad)
        logger.info("Employee data loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load employee data on startup: {e}")
    yield

app = FastAPI(
    title="Anonymizer API",
    description="API for anonymizing text strings with AD integration and pattern matching",
    version="1.0.0",
    lifespan=lifespan
)

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint returning API information"""
    return {
        "message": "Welcome to Anonymizer API",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify API status"""
    return {
        "status": "healthy",
        "service": "Universal Anonymizer API",
        "version": "1.0.0"
    }

@app.post("/anonymize", response_model=AnonymizeResponse, tags=["Anonymization"])
async def anonymize_endpoint(request: AnonymizeRequest):
    """
    Anonymize a list of text strings by replacing sensitive information with placeholders.
    
    This endpoint processes text strings and replaces:
    - Names with [[NAME]]
    - Email addresses with [[EMAIL_ADDRESS]]
    - Phone numbers with [[PHONE_NUMBER]]
    - IP addresses with [[IP_ADDRESS]]
    - Dates with [[DATE]]
    - Countries with [[COUNTRY]]
    - Cities with [[CITY]]
    - Employee USERIDs with [[USERID]]
    """
    try:
        logger.info(f"Starting anonymization for {len(request.texts)} texts")
        anonymized_texts = await anonymize_strings(request.texts)
        logger.info(f"Anonymization completed")
        return AnonymizeResponse(
            anonymized_texts=anonymized_texts
        )
    except Exception as e:
        logger.error(f"Anonymization failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Anonymization failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
