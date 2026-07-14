# MITM Attack Suite: ARP Spoofing + DNS Hijacking

Intercept LAN traffic via ARP spoofing and hijack DNS queries. No WiFi adapter required.

## Quick Start

```bash
git clone https://github.com/yourusername/mitm-attack-suite.git
cd mitm-attack-suite

pip install -r requirements.txt

# Edit targets
nano config/targets.yaml

sudo python3 src/main.py --config config/targets.yaml
