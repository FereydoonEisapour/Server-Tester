import os
import sys
import platform
import subprocess
import tempfile
import time
import json
import argparse
import logging
import threading
import queue
import requests
import shutil
import re
from urllib.parse import urlparse, parse_qs, unquote
from base64 import urlsafe_b64decode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from bs4 import BeautifulSoup
import base64

# Constants
V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
V2RAY_DIR = os.path.join(BASE_DIR, 'v2ray')
FILES_DIR = os.path.join(BASE_DIR, 'files')
RECIVED_DIR = os.path.join(BASE_DIR, 'recived_files')
SERVER_BY_TYPE_DIR = os.path.join(RECIVED_DIR, 'ServerByType')
TESTED_SERVERS_DIR = os.path.join(BASE_DIR, 'Tested_Servers')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 10
START_PORT = 10000
REQUEST_TIMEOUT = 30
PROCESS_START_WAIT = 15

# Protocol enable/disable configuration
ENABLED_PROTOCOLS = {
    'vless': True,
    'vmess': False,
    'trojan': False,
    'ss': False
}

def clean_directory(dir_path):
   
    if os.path.exists(dir_path):
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        logging.info(f"Cleaned directory: {dir_path}")
    else:
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")

# Create required directories
required_dirs = [
    FILES_DIR,
    RECIVED_DIR,
    SERVER_BY_TYPE_DIR,
    TESTED_SERVERS_DIR,
    os.path.join(TESTED_SERVERS_DIR, 'Protocols'),
    LOGS_DIR,
    V2RAY_DIR
]

for dir_path in required_dirs:
    os.makedirs(dir_path, exist_ok=True)

# Configure logging
class CleanFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            return f"{record.msg}"
        elif record.levelno == logging.ERROR:
            return f"ERROR: {record.msg}"
        return super().format(record)

# Set up logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Console handler (clean output)
console_handler = logging.StreamHandler()
console_handler.setFormatter(CleanFormatter())
logger.addHandler(console_handler)

# File handler (detailed logs)
file_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'debug.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Thread-safe port counter
current_port = START_PORT
port_lock = threading.Lock()

def get_next_port():
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
    return port

def download_content(url):
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch URL: {str(e)}")
    return None

def read_links_from_file(file_path):
    try:  
        with open(file_path, "r", encoding="utf-8") as file:
            links = file.readlines()
        return [link.strip() for link in links if link.strip()]
    except Exception as e:
        logging.error(f"Error reading file: {str(e)}")
        return []

def remove_duplicate_links(input_file):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            links = file.readlines()
        
        unique_links = list(set([link.strip() for link in links if link.strip()]))
        
        with open(input_file, "w", encoding="utf-8") as file:
            for link in unique_links:
                file.write(link + "\n")
        
        logging.info(f"Found {len(unique_links)} unique links")
        return unique_links
    except FileNotFoundError:
        logging.error("Input file not found")
        return []
    except Exception as e:
        logging.error(f"Error processing links: {str(e)}")
        return []

def process_and_save_links(links):
    def is_base64(s):
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False
    
    server_count = {}
    processed_lines = set()
    
    for index, link in enumerate(links):
        filename = link.split('/')[-1]
        logging.info(f"Processing {filename}")
        
        content = download_content(link)
        if content:
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line in processed_lines:
                    continue
                
                processed_lines.add(line)
                
                if line.startswith(('ss://', 'vmess://', 'vless://', 'trojan://')):
                    server_type = line.split("://")[0]
                    output_file = os.path.join(SERVER_BY_TYPE_DIR, f'{server_type.lower()}.txt')
                    with open(output_file, 'a', encoding='utf-8') as out_file:
                        out_file.write(line + '\n')
                    server_count[server_type] = server_count.get(server_type, 0) + 1
                
                elif is_base64(line):
                    try:
                        decoded = base64.b64decode(line).decode('utf-8')
                        json_data = json.loads(decoded)
                        server_type = json_data.get('ps', 'unknown').lower()
                        output_file = os.path.join(SERVER_BY_TYPE_DIR, f'{server_type}.txt')
                        with open(output_file, 'a', encoding='utf-8') as out_file:
                            out_file.write(json.dumps(json_data, ensure_ascii=False) + '\n')
                        server_count[server_type] = server_count.get(server_type, 0) + 1
                    except Exception:
                        pass

    logging.info("Server types found:")
    for server_type, count in server_count.items():
        logging.info(f"{server_type.upper()}: {count}")

def extract_links_from_file(input_file):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            links = [line.strip() for line in file if line.strip()]
        
        all_extracted_links = set()
        
        for link in links:
            filename = link.split('/')[-1]
            logging.info(f"Extracting from {filename}")
            
            try:
                response = requests.get(link, headers={'User-Agent': 'Mozilla/5.0'})
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                extracted_links = [a.get("href") for a in soup.find_all("a", href=True)]
                
                raw_links = []
                for extracted_link in extracted_links:
                    if extracted_link.startswith("http"):
                        raw_links.append(extracted_link)
                    elif extracted_link.startswith("/"):
                        raw_links.append(requests.compat.urljoin(link, extracted_link))
                
                filtered_links = [
                    rl.strip() for rl in raw_links 
                    if rl.strip().startswith(("https://github.com/", "https://raw.githubusercontent.com/")) and 
                    rl.strip().endswith((".txt", ".yaml", ".yml", ".md", ".conf"))
                ]
                
                raw_github_links = []
                for fl in filtered_links:
                    if "/blob/" in fl:
                        parts = fl.split("/")
                        username = parts[3]
                        repo = parts[4]
                        branch = parts[6]
                        path_to_file = "/".join(parts[7:])
                        raw_link = f"https://raw.githubusercontent.com/{username}/{repo}/{branch}/{path_to_file}"
                        raw_github_links.append(raw_link)
                    else:
                        raw_github_links.append(fl)
                
                all_extracted_links.update(raw_github_links)
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to process {filename}: {str(e)}")
        
        output_file = os.path.join(RECIVED_DIR, 'filtered_links.txt')
        with open(output_file, "w", encoding="utf-8") as file:
            for link in all_extracted_links:
                file.write(link + "\n")
        
        logging.info(f"Extracted {len(all_extracted_links)} links")
        return all_extracted_links
    except Exception as e:
        logging.error(f"Extraction failed: {str(e)}")
        return []

def parse_vless_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vless':
        raise ValueError("Invalid VLESS link")
    
    uuid = parsed.username
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uuid, re.I):
        raise ValueError("Invalid UUID format")
    
    query = parse_qs(parsed.query)
    return {
        'original_link': link,
        'protocol': 'vless',
        'uuid': uuid,
        'host': parsed.hostname,
        'port': parsed.port,
        'security': query.get('security', [''])[0] or 'none',
        'encryption': query.get('encryption', ['none'])[0],
        'network': query.get('type', ['tcp'])[0],
        'ws_path': query.get('path', [''])[0],
        'ws_host': query.get('host', [parsed.hostname])[0],
        'sni': query.get('sni', [parsed.hostname])[0] or parsed.hostname,
        'pbk': query.get('pbk', [''])[0],
        'sid': query.get('sid', [''])[0],
        'fp': query.get('fp', [''])[0],
        'alpn': query.get('alpn', [''])[0].split(',') if 'alpn' in query else [],
        'flow': query.get('flow', [''])[0]
    }

def parse_vmess_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vmess':
        raise ValueError("Invalid VMESS link")
    base64_data = parsed.netloc + parsed.path
    json_str = urlsafe_b64decode(base64_data + '==').decode('utf-8')
    data = json.loads(json_str)
    return {
        'original_link': link,
        'protocol': 'vmess',
        'uuid': data.get('id'),
        'host': data.get('add'),
        'port': int(data.get('port', 80)),
        'network': data.get('net', 'tcp'),
        'security': data.get('tls', 'none'),
        'ws_path': data.get('path', ''),
        'ws_host': data.get('host', ''),
        'sni': data.get('sni', ''),
        'alter_id': int(data.get('aid', 0)),
        'encryption': 'none'
    }

def parse_trojan_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'trojan':
        raise ValueError("Invalid Trojan link")
    query = parse_qs(parsed.query)
    return {
        'original_link': link,
        'protocol': 'trojan',
        'password': parsed.username,
        'host': parsed.hostname,
        'port': parsed.port,
        'security': query.get('security', ['tls'])[0],
        'sni': query.get('sni', [parsed.hostname])[0],
        'alpn': query.get('alpn', ['h2,http/1.1'])[0].split(','),
        'network': query.get('type', ['tcp'])[0],
        'ws_path': query.get('path', [''])[0],
        'ws_host': query.get('host', [parsed.hostname])[0]
    }

def parse_ss_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'ss':
        raise ValueError("Invalid Shadowsocks link")

    try:
        userinfo = unquote(parsed.netloc)

       
        if '@' in userinfo:
            base64_part, _ = userinfo.split('@', 1)
            try:
                padding = '=' * ((4 - len(base64_part) % 4) % 4)
                decoded = urlsafe_b64decode(base64_part + padding).decode('utf-8')
                if ':' not in decoded:
                    raise ValueError("Decoded Shadowsocks info missing ':' separator")
                method, password = decoded.split(':', 1)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 method:password — {str(e)}")
       
        elif ':' in userinfo:
            method, password = userinfo.split(':', 1)
        else:
            raise ValueError("Shadowsocks link missing proper format (no @ or :)")

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            raise ValueError("Missing host or port in Shadowsocks link")

        return {
            'original_link': link,
            'protocol': 'shadowsocks',
            'method': method,
            'password': password,
            'host': host,
            'port': int(port),
            'network': 'tcp'
        }

    except Exception as e:
        raise ValueError(f"Invalid Shadowsocks link format: {str(e)}")





def generate_config(server_info, local_port):
    config = {
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": server_info['protocol'],
            "settings": {},
            "streamSettings": {}
        }]
    }
    
    if server_info['protocol'] == 'vless':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "encryption": server_info['encryption'],
                    "flow": server_info.get('flow', '')
                }]
            }]
        }
    elif server_info['protocol'] == 'vmess':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "alterId": server_info['alter_id'],
                    "security": server_info['encryption']
                }]
            }]
        }
    elif server_info['protocol'] == 'trojan':
        config['outbounds'][0]['settings'] = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "password": server_info['password']
            }]
        }
    elif server_info['protocol'] == 'shadowsocks':
        config['outbounds'][0]['settings'] = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "method": server_info['method'],
                "password": server_info['password'],
                "ota": False
            }]
        }
    
    stream = {
        "network": server_info.get('network', 'tcp'),
        "security": server_info.get('security', 'none'),
        "tlsSettings": None,
        "realitySettings": None,
        "wsSettings": None
    }
    
    if server_info.get('security') == 'tls':
        stream['tlsSettings'] = {
            "allowInsecure": True,
            "serverName": server_info.get('sni'),
            "alpn": server_info.get('alpn', [])
        }
    elif server_info.get('security') == 'reality':
        stream['realitySettings'] = {
            "show": False,
            "fingerprint": server_info.get('fp', ''),
            "serverName": server_info.get('sni'),
            "publicKey": server_info.get('pbk', ''),
            "shortId": server_info.get('sid', ''),
            "spiderX": ""
        }
    
    if server_info.get('network') == 'ws':
        stream['wsSettings'] = {
            "path": server_info.get('ws_path', ''),
            "headers": {
                "Host": server_info.get('ws_host', '')
            }
        }
    
    config['outbounds'][0]['streamSettings'] = {k: v for k, v in stream.items() if v is not None}
    return config

def test_server(server_info, config, local_port, log_queue):
    process = None
    config_path = None
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
            json.dump(config, f)
            config_path = f.name
        
        v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
        logging.info(f"Testing {server_info['host']}:{server_info['port']}")
        
        process = subprocess.Popen(
            [v2ray_path, 'run', '--config', config_path],
            cwd=V2RAY_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(PROCESS_START_WAIT)
        
        if process.poll() is not None:
            stderr = process.stderr.read().decode()
            raise RuntimeError(f"V2Ray failed to start: {stderr}")
        
        proxies = {
            'http': f'socks5h://127.0.0.1:{local_port}',
            'https': f'socks5h://127.0.0.1:{local_port}'
        }
        
        start_time = time.time()
        response = requests.get(
            TEST_LINK,
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            log_queue.put(('success', server_info, f"{elapsed:.2f}s"))
        else:
            log_queue.put(('failure', server_info, f"HTTP {response.status_code}"))
            
    except requests.exceptions.RequestException as e:
        log_queue.put(('failure', server_info, f"Request failed: {str(e)}"))
    except Exception as e:
        log_queue.put(('failure', server_info, f"Test error: {str(e)}"))
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        if config_path and os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception:
                pass

def check_v2ray_installed():
    try:
        result = subprocess.run(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), 'version'],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            check=True
        )
        output = result.stdout.decode('utf-8')
        version = output.split()[1]
        return version
    except Exception:
        return None

def get_latest_version():
    try:
        response = requests.get(
            'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
            timeout=5
        )
        response.raise_for_status()
        return response.json()['tag_name'].lstrip('v')
    except requests.exceptions.RequestException:
        return None

def install_v2ray():
    try:
        os_type = platform.system().lower()
        base_url = 'https://github.com/v2fly/v2ray-core/releases/latest/download'
        
        if os_type == 'linux':
            machine = platform.machine().lower()
            if 'aarch64' in machine or 'arm64' in machine:
                url = f'{base_url}/v2ray-linux-arm64.zip'
            else:
                url = f'{base_url}/v2ray-linux-64.zip'
        elif os_type == 'windows':
            url = f'{base_url}/v2ray-windows-64.zip'
        else:
            raise OSError(f"Unsupported OS: {os_type}")

        if os.path.exists(V2RAY_DIR):
            shutil.rmtree(V2RAY_DIR, ignore_errors=True)
        os.makedirs(V2RAY_DIR, exist_ok=True)

        try:
            import zipfile
            import urllib.request
            zip_path, _ = urllib.request.urlretrieve(url)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(V2RAY_DIR)
            
            v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
            os.chmod(v2ray_path, 0o755)
            
            result = subprocess.run(
                [v2ray_path, 'version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise RuntimeError(f"V2Ray install failed: {result.stderr.decode()}")
                
        except Exception as e:
            sys.exit(f"Installation failed: {e}")
    except Exception as e:
        logging.critical(f"V2Ray installation failed: {e}")
        sys.exit(1)

def logger_thread(log_queue):
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    os.makedirs(protocols_dir, exist_ok=True)
    
    log_file = os.path.join(LOGS_DIR, 'latest_log.txt')
    working_file = os.path.join(TESTED_SERVERS_DIR, 'working_servers.txt')
    dead_file = os.path.join(TESTED_SERVERS_DIR, 'dead_servers.txt')
    skip_file = os.path.join(TESTED_SERVERS_DIR, 'skipped_servers.txt')
    
    with open(log_file, 'a') as log_f, \
         open(working_file, 'a') as working_f, \
         open(dead_file, 'a') as dead_f, \
         open(skip_file, 'a') as skip_f:
         
        while True:
            record = log_queue.get()
            if record is None:
                break
            status, server_info, message = record
            
            protocol = server_info.get('protocol', 'N/A').upper()
            host = server_info.get('host', 'N/A')
            port = server_info.get('port', 'N/A')
            
            if status == 'success':
                logging.info(f"{protocol} {host}:{port} - Connected ({message})")
            elif status == 'skip':
                logging.info(f"{protocol} {host}:{port} - Skipped ({message})")
            else:
                logging.error(f"{protocol} {host}:{port} - Failed ({message})")
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_f.write(
                f"[{timestamp}] {protocol} {host}:{port} - {status.upper()} - {message}\n"
            )
            
            if status == 'success':
                working_f.write(f"{server_info['original_link']}\n")
                protocol_file = os.path.join(protocols_dir, f"{server_info.get('protocol', 'unknown').lower()}.txt")
                with open(protocol_file, 'a') as pf:
                    pf.write(f"{server_info['original_link']}\n")
            elif status == 'skip':
                skip_f.write(f"{server_info['original_link']}|{message}\n")
            else:
                dead_f.write(f"{server_info['original_link']}|{message}\n")
            
            log_f.flush()
            working_f.flush()
            dead_f.flush()
            skip_f.flush()

if __name__ == "__main__":

    logging.info("Cleaning previous data...")
    clean_directory(RECIVED_DIR)
    clean_directory(TESTED_SERVERS_DIR)
    
    os.makedirs(SERVER_BY_TYPE_DIR, exist_ok=True)
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)
    
    sys.stdout.reconfigure(encoding='utf-8')
    logging.info("Starting server tester")
    
    # Process links
    input_file = os.path.join(FILES_DIR, 'git_links.txt')
    unique_links = remove_duplicate_links(input_file)
    
    if not unique_links:
        logging.error("No valid links found")
        sys.exit(1)
    
    filtered_links = extract_links_from_file(input_file)
    if filtered_links:
        process_and_save_links(filtered_links)
    else:
        logging.error("No servers to test")
        sys.exit(1)
    
    # Test servers
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS)
    args = parser.parse_args()
    
    logging.info("Protocol configuration:")
    for proto, enabled in ENABLED_PROTOCOLS.items():
        logging.info(f"  {proto.upper():<10}: {'Enabled' if enabled else 'Disabled'}")
    
    # Check V2Ray installation
    installed_version = check_v2ray_installed()
    latest_version = get_latest_version()
    
    if not installed_version or (latest_version and installed_version != latest_version):
        logging.info("Installing V2Ray...")
        install_v2ray()
    else:
        logging.info(f"Using V2Ray {installed_version}")
    
    # Load servers
    servers = []
    try:
        for filename in os.listdir(SERVER_BY_TYPE_DIR):
            if filename.endswith('.txt'):
                proto = filename.split('.')[0].lower()
                if proto in ENABLED_PROTOCOLS and not ENABLED_PROTOCOLS[proto]:
                    continue
                
                file_path = os.path.join(SERVER_BY_TYPE_DIR, filename)
                with open(file_path, 'r') as f:
                    servers.extend([line.strip() for line in f if line.strip()])
        
        logging.info(f"Loaded {len(servers)} servers for testing")
    except Exception as e:
        logging.error(f"Failed to load servers: {str(e)}")
        sys.exit(1)
    
    # Start testing
    log_queue = queue.Queue()
    logger = threading.Thread(target=logger_thread, args=(log_queue,))
    logger.start()
    
    with ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        futures = []
        for link in servers:
            try:
                parsed = urlparse(link)
                proto = parsed.scheme.lower()
                
                if proto not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[proto]:
                    log_queue.put(('skip', {'original_link': link, 'protocol': proto, 
                                          'host': 'N/A', 'port': 'N/A'}, 
                                "Protocol disabled"))
                    continue
                
                if proto == 'vless':
                    server_info = parse_vless_link(link)
                elif proto == 'vmess':
                    server_info = parse_vmess_link(link)
                elif proto == 'trojan':
                    server_info = parse_trojan_link(link)
                elif proto == 'ss':
                    server_info = parse_ss_link(link)
                else:
                    log_queue.put(('skip', {'original_link': link, 'protocol': proto,
                                          'host': 'N/A', 'port': 'N/A'},
                                "Unsupported protocol"))
                    continue
                
                local_port = get_next_port()
                config = generate_config(server_info, local_port)
                futures.append(executor.submit(test_server, server_info, config, local_port, log_queue))
                
            except Exception as e:
                log_queue.put(('failure', {'original_link': link, 'protocol': 'unknown',
                                          'host': 'N/A', 'port': 'N/A'},
                            f"Parse error: {str(e)}"))
        
        for future in futures:
            future.result()
    
    log_queue.put(None)
    logger.join()
    logging.info("Testing completed")
