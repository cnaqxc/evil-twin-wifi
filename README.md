# Evil Twin WiFi

A complete evil twin access point in software. No monitor mode required. Clone, configure, run.

## Quick Start

```bash
git clone https://github.com/username/evil-twin-wifi.git
cd evil-twin-wifi
sudo bash tools/install_deps.sh
sudo python3 src/ap_server.py --config config/ap_config.yaml
