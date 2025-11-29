# SW

Modified by **Shahriyar Sojib Hasan**

This project is a customized version of OneShot, renamed and re‑branded for personal use.

# Overview

**SW (formerly OneShot)** performs [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) without having to switch to monitor mode.

# Modifications

* `oneshot.py` renamed to **sw.py**
* Owner/Developer updated: **Shahriyar Sojib Hasan**
* GUI support through **update.py**

# Features

* [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack)
* Integrated [3WiFi offline WPS PIN generator](https://3wifi.stascorp.com/wpspin)
* [Online WPS bruteforce](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf)
* Wi‑Fi scanner with highlighting based on `iw`

# Requirements

* Python 3.6+
* wpa_supplicant
* pixiewps
* iw

# Setup

## Debian/Ubuntu

**Install requirements:**

```
sudo apt install -y python3 wpasupplicant iw wget
```

**Install Pixiewps:**

```
sudo apt install -y pixiewps
```

**Get SW:**

```
wget https://raw.githubusercontent.com/shahriyarsojibhasan/SW/master/sw.py
```

Optional vulnerable device list:

```
wget https://raw.githubusercontent.com/shahriyarsojibhasan/SW/master/vulnwsc.txt
```

## Arch Linux

```
sudo pacman -S wpa_supplicant pixiewps wget python
wget https://raw.githubusercontent.com/shahriyarsojibhasan/SW/master/sw.py
```

## Alpine Linux

```
sudo apk add python3 wpa_supplicant pixiewps iw
sudo wget https://raw.githubusercontent.com/shahriyarsojibhasan/SW/master/sw.py
```

## Termux (Root required)

### Installing requirements

```
pkg install -y root-repo
pkg install -y git tsu python wpa-supplicant pixiewps iw openssl
```

### Getting SW

```
git clone --depth 1 https://github.com/shahriyarsojibhasan/SW SW
```

### Running

```
sudo python SW/sw.py -i wlan0 --iface-down -K
```

Run:

```
sudo python SW/sw.py -i wlan0 --iface-down -K
```

# Usage

```
sw.py <arguments>

Required:
  -i, --interface=<wlan0>

Optional:
  -b --bssid=<mac>
  -p --pin=<wps pin>
  -K --pixie-dust
  -B --bruteforce
  --push-button-connect

Advanced:
  -d --delay=<n>
  -w --write
  -F --pixie-force
  -X --show-pixie-cmd
  --vuln-list=<file>
  --iface-down
  -l --loop
  -r --reverse-scan
  --mtk-wifi
  -v --verbose
```

# Examples

```
sudo python3 sw.py -i wlan0 -b 00:90:4C:C1:AC:21 -K
sudo python3 sw.py -i wlan0 -K
sudo python3 sw.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234
sudo python3 sw.py -i wlan0 --pbc
```

# GUI (update.py)

GUI launcher is available at:

```
python3 update.py
```

# Troubleshooting

* RF‑kill error → `sudo rfkill unblock wifi`
* Busy device → disable Wi‑Fi or use `--iface-down`
* MTK Wi-Fi disappearing → use `--mtk-wifi`

# Owner / Maintainer

**Shahriyar Sojib Hasan**
