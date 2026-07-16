#!/usr/bin/env bash

set -euo pipefail

interface="${1:-wlan0}"

if [[ $EUID -ne 0 ]]; then
    printf 'Run this command with sudo: sudo %q %q\n' "$0" "$interface" >&2
    exit 1
fi

if [[ ! -d "/sys/class/net/$interface" ]]; then
    printf 'Network interface does not exist: %s\n' "$interface" >&2
    exit 1
fi

connection="$(nmcli -g GENERAL.CONNECTION device show "$interface")"
if [[ -z "$connection" || "$connection" == "--" ]]; then
    printf 'No active NetworkManager connection on %s\n' "$interface" >&2
    exit 1
fi

phy_path="$(readlink -f "/sys/class/net/$interface/phy80211")"
if [[ -z "$phy_path" ]]; then
    printf 'Could not determine wireless PHY for %s\n' "$interface" >&2
    exit 1
fi
phy="${phy_path##*/}"

nmcli connection modify "$connection" 802-11-wireless.wake-on-wlan magic
iw phy "$phy" wowlan enable magic-packet
printf 'enabled\n' > "/sys/class/net/$interface/device/power/wakeup"

printf 'Configured Wake-on-WLAN for connection %s on %s (%s).\n' \
    "$connection" "$interface" "$phy"
printf 'NetworkManager setting: '
nmcli -g 802-11-wireless.wake-on-wlan connection show "$connection"
printf 'Kernel setting: '
iw phy "$phy" wowlan show
printf 'PCI wake setting: '
cat "/sys/class/net/$interface/device/power/wakeup"
