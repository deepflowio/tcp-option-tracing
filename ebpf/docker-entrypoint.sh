#!/bin/sh
mount -t debugfs none /sys/kernel/debug/

exec "$@"
