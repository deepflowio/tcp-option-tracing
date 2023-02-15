# tcp-option-tracing

TCP Option Tracing 是一个内核模块. 通过 TCP Option 向对端发送用于追踪的进程号,源地址和 TCP 序列号.

## 如何工作

受到 [IPVS 的 TOA](https://github.com/alibaba/LVS/blob/2c7f867baada4cc00226f492c65f6e6f22cbb2d1/kernel/net/netfilter/ipvs/ip_vs_proto_tcp.c#L732) 的启发. 这个项目使用 netfilter 在 TCP 报文的 Option 中加入自定义字段. 新增字段按照 [rfc6994](https://datatracker.ietf.org/doc/rfc6994/) 定义报文格式.

## 支持的内核

这个模块支持 3.10+ 内核. 在 centos7 的 3.10.0-1160.81.1.el7.x86_64 和 archlinux 的 5.15.90-1-lts 通过测试.

## 安装与卸载

默认情况下,开启 TCP Push 报文抽样, 每满 16KB 添加一次 TOT. 可以通过环境变量关闭抽样.

```bash
export DISABLE_SAMPLING=true
```

默认情况下,产生完整 TOT 报文(16字节). 当 TCP Option 可用字段不足时,可以选择屏蔽某些字段.

```bash
# 屏蔽 TCP 序列号
export DISABLE_TCPSEQ=true

# 屏蔽源地址
export DISABLE_SADDR=true
```

其他操作与普通内核模块安装卸载方式一致.可以参考 [TOA插件配置](https://support.huaweicloud.com/usermanual-elb/zh_cn_elb_06_0001.html).
