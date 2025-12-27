#!/bin/bash
mkdir -p /tmp/xdp_audit

uname -a > /tmp/xdp_audit/uname.txt
cat /etc/os-release > /tmp/xdp_audit/os.txt
clang --version > /tmp/xdp_audit/clang.txt 2>&1
bpftool version > /tmp/xdp_audit/bpftool.txt 2>&1
pkg-config --modversion libbpf > /tmp/xdp_audit/libbpf.txt 2>&1
mount | grep bpf > /tmp/xdp_audit/mount.txt
sysctl net.core.bpf_jit_enable > /tmp/xdp_audit/jit.txt
ulimit -l > /tmp/xdp_audit/ulimit.txt
ip -details link > /tmp/xdp_audit/ip.txt
