INTERFACE=ens33
NEXT_HOP=192.168.209.2

sudo ip netns add space

# setting up loopback
sudo ip netns exec space ip link set dev lo up

# create two virtual interfaces to be used later to connect 'space' to root
sudo ip link add veth0 type veth peer name veth1

# add 'veth1' to 'space' namespace to allow connection between the namespaces
sudo ip link set veth1 netns space


# configure ip for 'veth0' and turn it on
sudo ip addr add 192.168.0.1/24 dev veth0
sudo ip link set dev veth0 up

# configure ip for 'veth1' and turn it on
sudo ip netns exec space ip addr add 192.168.0.2/24 dev veth1
sudo ip netns exec space ip link set dev veth1 up

# configure default gateway inside 'space'
sudo ip netns exec space ip route add default via 192.168.0.1


# make the host a router:

# tell the host it can route stuff
sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# drop all packets by default
sudo iptables -P FORWARD DROP

# add MASQUERADE to our subnet and out from out phisical interface
sudo iptables -t nat -A POSTROUTING -s 192.168.0.0/255.255.255.0 -o $INTERFACE -j MASQUERADE

# allow forwarding to both directions
sudo iptables -A FORWARD -i $INTERFACE -o veth0 -j ACCEPT
sudo iptables -A FORWARD -o $INTERFACE -i veth0 -j ACCEPT

# TODO: add a routing table:
#/etc/iproute2/rt_tables
#
# 255 local
# 254 main
# 253 default
# 0 unspec
# 100 test <- add this line

# remove the default routing rules
echo removing default gateway
sudo ip route del default dev $INTERFACE
echo showing routing table
sudo ip route show

# add a rule to route only if it comes from eth1
sudo ip rule add from 192.168.0.2 table test
sudo ip route add default via $NEXT_HOP dev $INTERFACE table test
