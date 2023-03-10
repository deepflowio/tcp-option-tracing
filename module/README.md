## supported kernel

This module supports 3.10+ kernels. Tested on 3.10.0-1160.81.1.el7.x86_64 on centos7 and 5.15.90-1-lts on archlinux.

## Install and Uninstall

By default, TCP Push packet sampling is enabled, and TOT is added every 16KB. Sampling can be disabled through environment variables.

```bash
export DISABLE_SAMPLING=true
```

By default, a complete TOT message (16 bytes) is generated. When the available fields of TCP Option are insufficient, some fields can be selected to be disabled.

```bash
# Disable TCP Sequence Numbers
export DISABLE_TCPSEQ=true

# Disable source address
export DISABLE_SADDR=true
```

Other operations are consistent with the installation and uninstallation methods of ordinary kernel modules. You can refer to [Configuring the TOA Module](https://support.huaweicloud.com/intl/en-us/ga_faq/ga_05_9001.html)
