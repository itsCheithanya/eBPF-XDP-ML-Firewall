sudo clang -O2 -g -target bpf -c $1.c -o $1.o
if test -f /sys/fs/bpf/$1; then
echo "Already Exists"
sudo rm /sys/fs/bpf/$1
fi
sudo bpftool net detach xdp dev $2
sudo bpftool prog load $1.o /sys/fs/bpf/$1
sudo bpftool net -d attach  xdp name $1 dev $2 overwrite
