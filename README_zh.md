# tcp-option-tracing

TCP Option Tracing 通过 TCP Option 向对端发送用于追踪的进程号,源地址和 TCP 序列号. 有内核模块和 eBPF 两种实现方式.

## 如何工作

受到 [IPVS 的 TOA](https://github.com/alibaba/LVS/blob/2c7f867baada4cc00226f492c65f6e6f22cbb2d1/kernel/net/netfilter/ipvs/ip_vs_proto_tcp.c#L732) 的启发. 这个项目使用 netfilter 或 eBPF 在 TCP 报文的 Option 中加入自定义字段. 新增字段按照 [rfc6994](https://datatracker.ietf.org/doc/rfc6994/) 定义报文格式.
