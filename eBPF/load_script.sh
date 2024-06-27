sudo clang -O2 -g -target bpf -c $1.c -o $1.o
sudo gcc $2.c -lbpf -lxdp
sudo ./a.out $3
