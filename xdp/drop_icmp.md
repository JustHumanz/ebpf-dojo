### Clang
- `clang -O2 -target bpf -c drop_icmp.c -o drop_icmp.o`
- `ip link set dev <dev> xdp obj <file> sec <function>`
- `ip link show dev <dev>`
- `ip link set dev <dev> xdp off`

### Iptables
- `iptables -A INPUT -p icmp -j DROP`