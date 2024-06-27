if test -f /sys/fs/bpf/$1; then
echo "Already Exists"
sudo rm /sys/fs/bpf/$1
fi
sudo bpftool net detach xdp dev $2
