# tcp-option-tracing

TCP Option Tracing is a kernel module. Send the process number, source address and TCP sequence number for tracking to the peer through TCP Option.

## how to work

Inspired by the [TOA of IPVS](https://github.com/alibaba/LVS/blob/2c7f867baada4cc00226f492c65f6e6f22cbb2d1/kernel/net/netfilter/ipvs/ip_vs_proto_tcp.c#L732). This project uses netfilter to add custom fields in the Option of TCP packets. The new fields define the packet format according to [rfc6994](https://datatracker.ietf.org/doc/rfc6994/).

## supported kernel

This module supports 3.10+ kernels. Tested on 3.10.0-1160.81.1.el7.x86_64 on centos7 and 5.15.90-1-lts on archlinux.

## Install and Uninstall

The installation and uninstallation method is the same as that of ordinary kernel modules. You can refer to [Configuring the TOA Module](https://support.huaweicloud.com/intl/en-us/ga_faq/ga_05_9001.html)
