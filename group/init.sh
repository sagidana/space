USER=s
INTERNET_GROUP=allow-internet

# create 'allow-internet' group if not exist
sudo groupadd $INTERNET_GROUP
# add current user to group if not already there
sudo gpasswd -a $USER $INTERNET_GROUP

# clear all iptables rules
sudo iptables -F

# TODO: disable internet for the current user
sudo iptables -I OUTPUT 1 -m owner --gid-owner $USER -j DROP

# sudo iptables -I OUTPUT 1 -m owner --gid-owner $USER -j ACCEPT

