INTERFACE=ens33
NEXT_HOP=192.168.209.2

# TODO: destroy the leftover pids using this namespace

sudo ip netns del space

# remove routing for test table
sudo ip route del default dev $INTERFACE table test

# re-add the default routing rules
sudo ip route add default via $NEXT_HOP dev $INTERFACE

