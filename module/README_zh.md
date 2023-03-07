## 支持的内核

内核模块支持 3.10+ 内核. 在 centos7 的 3.10.0-1160.81.1.el7.x86_64 和 archlinux 的 5.15.90-1-lts 通过测试.

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
