## ebpf dojo

this repo will contain PoC of ebpf training

#### Ref
- https://www.sobyte.net/post/2022-07/c-ebpf/
- https://organicprogrammer.com/2022/05/04/how-to-write-a-netfilter-firewall-part1/
- https://organicprogrammer.com/2022/05/04/how-to-write-a-netfilter-firewall-part2/
- https://organicprogrammer.com/2022/05/04/how-to-write-a-netfilter-firewall-part3/
- https://gist.github.com/satrobit/17eb0ddd4e122425d96f60f45def9627
- https://fnordig.de/2017/03/04/send-icmp-echo-replies-using-ebpf/
- https://arthurchiao.art/blog/cracking-k8s-node-proxy/#7-implementation-4-proxy-via-tc-level-ebpf
- https://arthurchiao.art/blog/firewalling-with-bpf-xdp/
- https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
- https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control
- https://www.tkng.io/services/clusterip/dataplane/ebpf/
- https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections/
- https://blog.devgenius.io/how-to-write-ebpf-programs-with-golang-933d58fc5dba
- https://marselester.com/bpf-go-frontend-for-execsnoop.html
- https://github.com/fbac/sklookup-go

#### bpftool
- bpftool prog load socket_nat.o /sys/fs/bpf/humanz_proxy
- bpftool cgroup attach /sys/fs/cgroup/unified/user.slice connect4 pinned /sys/fs/bpf/humanz_proxy
- bpftool cgroup show /sys/fs/cgroup/unified/user.slice
- bpftool cgroup detach /sys/fs/cgroup/unified/user.slice cgroup_inet4_connect name connect4_lb
- bpftool map dump pinned /sys/fs/bpf/humanz_proxy