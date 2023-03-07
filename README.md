# tcp-option-tracing

TCP Option Tracing is a kernel module. Send the process number, source address and TCP sequence number for tracking to the peer through TCP Option.

## how to work

Inspired by the [TOA of IPVS](https://github.com/alibaba/LVS/blob/2c7f867baada4cc00226f492c65f6e6f22cbb2d1/kernel/net/netfilter/ipvs/ip_vs_proto_tcp.c#L732). This project uses netfilter or eBPF to add custom fields in the Option of TCP packets. The new fields define the packet format according to [rfc6994](https://datatracker.ietf.org/doc/rfc6994/).
