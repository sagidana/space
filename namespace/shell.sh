USER=s

sudo ip netns exec space /bin/bash -c 'su $USER'

# sudo ip netns exec space capsh --user="$USER" --caps="cap_net_raw=eip" --keep=1 --
