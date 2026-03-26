#!/bin/bash

# Create 8 TAP interfaces: tap0-tap3 and tap11-tap14
# Assign IPs but DO NOT configure any gateway or routing

declare -A IPS=(
  [tap0]="192.168.100.2/24"
  [tap1]="192.168.100.3/24"
  [tap2]="192.168.200.4/24"
  [tap3]="192.168.200.5/24"
  [tap11]="192.168.110.2/24"
  [tap12]="192.168.110.3/24"
  [tap13]="192.168.120.4/24"
  [tap14]="192.168.120.5/24"
)

for IFACE in tap0 tap1 tap2 tap3 tap11 tap12 tap13 tap14; do
    echo "Creating $IFACE..."

    sudo ip tuntap add dev "$IFACE" mode tap
    sudo ip link set dev "$IFACE" up
    sudo ip addr add "${IPS[$IFACE]}" dev "$IFACE"

    echo "$IFACE configured with IP ${IPS[$IFACE]}"
done

echo "All TAP interfaces created successfully (NO gateway added)."
