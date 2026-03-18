#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# rtnetlink_vm.sh
# Boot a minimal Alpine Linux VM in QEMU and run the RTNetlink live tests.
#
# Usage: bash .config/ci/rtnetlink_vm.sh
#
# Required tools (installed by the CI workflow before calling this script):
#   qemu-system-x86_64, qemu-img, expect, ssh, scp, wget

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALPINE_VERSION="3.23.3"
ALPINE_MINOR="${ALPINE_VERSION%.*}"           # e.g.  3.23
ALPINE_ISO_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MINOR}/releases/x86_64/alpine-virt-${ALPINE_VERSION}-x86_64.iso"

ALPINE_ISO="/tmp/alpine-virt-${ALPINE_VERSION}.iso"
VM_DISK="/tmp/alpine-vm.qcow2"
SSH_PORT="2222"
SSH_KEY="/tmp/vm_ed25519_key"
SCAPY_TAR="/tmp/scapy-src.tar.gz"

# Absolute path to the repo root (two directories up from this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Phase 1: Download Alpine Linux virt ISO
# ---------------------------------------------------------------------------
echo "=== Downloading Alpine Linux ${ALPINE_VERSION} virt ISO ==="
if [ ! -f "${ALPINE_ISO}" ]; then
    wget --quiet --show-progress --tries=3 \
        -O "${ALPINE_ISO}" "${ALPINE_ISO_URL}" || {
        echo "ERROR: Failed to download Alpine Linux ISO from ${ALPINE_ISO_URL}"
        exit 1
    }
fi
echo "ISO ready: $(du -sh "${ALPINE_ISO}" | cut -f1)"

# ---------------------------------------------------------------------------
# Phase 2: Create VM disk image
# ---------------------------------------------------------------------------
echo "=== Creating VM disk image ==="
qemu-img create -f qcow2 "${VM_DISK}" 2G -q

# ---------------------------------------------------------------------------
# Phase 3: Generate SSH key for VM access
# ---------------------------------------------------------------------------
echo "=== Generating SSH key pair ==="
rm -f "${SSH_KEY}" "${SSH_KEY}.pub"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q
SSH_PUBKEY="$(cat "${SSH_KEY}.pub")"

# ---------------------------------------------------------------------------
# Phase 4: Package the scapy source for transfer into the VM
# ---------------------------------------------------------------------------
echo "=== Packaging Scapy source ==="
tar czf "${SCAPY_TAR}" \
    -C "${REPO_ROOT}" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    scapy/ test/

# ---------------------------------------------------------------------------
# Phase 5: Export variables consumed by the embedded expect script
# ---------------------------------------------------------------------------
export ALPINE_ISO VM_DISK SSH_PORT SSH_KEY SSH_PUBKEY SCAPY_TAR

if [ -e /dev/kvm ]; then
    echo "KVM acceleration: enabled"
    export QEMU_KVM_FLAG="1"
else
    echo "KVM acceleration: not available (using TCG - slower)"
    export QEMU_KVM_FLAG="0"
fi

# ---------------------------------------------------------------------------
# Phase 6: Boot Alpine, configure SSH, run tests (all via expect)
# ---------------------------------------------------------------------------
echo "=== Starting Alpine VM and running RTNetlink live tests ==="

expect << 'EXPECT_EOF'
# ------------------------------------------------------------------
# Expect script: boot Alpine, configure SSH, copy scapy, run tests
# ------------------------------------------------------------------
set timeout 300
log_user 1

set alpine_iso  $env(ALPINE_ISO)
set vm_disk     $env(VM_DISK)
set ssh_port    $env(SSH_PORT)
set ssh_key     $env(SSH_KEY)
set ssh_pubkey  $env(SSH_PUBKEY)
set scapy_tar   $env(SCAPY_TAR)
set kvm_flag    $env(QEMU_KVM_FLAG)

# ---- Build the QEMU command as a proper list so quoting is correct ----
set qemu_cmd [list qemu-system-x86_64 \
    -m 512M \
    -smp 2 \
    -drive  "file=$vm_disk,format=qcow2,if=virtio" \
    -cdrom  $alpine_iso \
    -boot   order=d \
    -netdev "user,id=net0,hostfwd=tcp::${ssh_port}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic]

if {$kvm_flag eq "1"} {
    lappend qemu_cmd -enable-kvm
}

# ---- Boot the VM ----
puts "Booting Alpine Linux VM..."
eval spawn $qemu_cmd

# ---- Wait for the login prompt (Alpine virt boots in ~15s with KVM) ----
expect {
    -re "login:" { puts "VM boot: login prompt received" }
    timeout {
        puts stderr "ERROR: Alpine VM did not reach login prompt within 300 s"
        exit 1
    }
}

# ---- Log in as root (no password on Alpine virt) ----
send "root\r"
expect "# "

# ---- Wait for network (DHCP may not be complete right after login) ----
# Poll for a default route for up to 30 s; fall back to explicit udhcpc if absent.
puts "Waiting for network..."
send "for i in \$(seq 1 30); do ip route show default | grep -q default && echo NET_READY && break; sleep 1; done\r"
expect {
    "NET_READY" { puts "Network is up (default route present)" }
    timeout {
        puts stderr "ERROR: No default route after 30 s - network unavailable"
        exit 1
    }
}
expect "# "

# ---- Install required packages (errors visible; exit on failure) ----
puts "Installing packages..."
set timeout 120
send "apk update\r"
expect {
    "# "    { }
    timeout { puts stderr "ERROR: apk update timed out"; exit 1 }
}

send "apk add openssh python3 iproute2\r"
expect {
    "# "    { }
    timeout { puts stderr "ERROR: Package installation timed out"; exit 1 }
}
set timeout 300

# Abort early if the sshd binary is missing (openssh install failed).
send "ls /usr/sbin/sshd && echo SSHD_OK || echo SSHD_MISSING\r"
expect {
    "SSHD_OK"      { puts "sshd binary confirmed" }
    "SSHD_MISSING" {
        puts stderr "ERROR: /usr/sbin/sshd not found - openssh install failed"
        exit 1
    }
    timeout { puts stderr "ERROR: timeout checking sshd binary"; exit 1 }
}
expect "# "
puts "Packages installed"

# ---- Load dummy kernel module (for test interfaces) ----
send "modprobe dummy 2>/dev/null || true\r"
expect "# "

# ---- Configure SSH daemon ----
puts "Configuring SSH..."
send "mkdir -p /root/.ssh && chmod 700 /root/.ssh\r"
expect "# "

# Write the public key using printf to avoid special-character issues
send "printf '%s\\n' '$ssh_pubkey' > /root/.ssh/authorized_keys\r"
expect "# "
send "chmod 600 /root/.ssh/authorized_keys\r"
expect "# "

# Append to the existing sshd_config installed by the openssh package.
send "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config\r"
expect "# "

# Use Alpine's OpenRC service: it generates host keys and starts sshd.
send "rc-service sshd start\r"
expect "# "
puts "SSH daemon started"

# ---- Wait for SSH to be reachable ----
puts "Waiting for SSH to become reachable..."
set ssh_ready 0
for {set i 0} {$i < 30} {incr i} {
    if {![catch {
        exec ssh \
            -p $ssh_port \
            -i $ssh_key \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=2 \
            -o LogLevel=ERROR \
            root@127.0.0.1 \
            "echo SSH_OK"
    }]} {
        set ssh_ready 1
        break
    }
    after 1000
}
if {!$ssh_ready} {
    puts stderr "ERROR: SSH did not become reachable within 30 s"
    exit 1
}
puts "SSH is reachable"

# ---- Copy Scapy source into the VM ----
puts "Copying Scapy source to VM..."
exec scp \
    -P $ssh_port \
    -i $ssh_key \
    -o StrictHostKeyChecking=no \
    -o LogLevel=ERROR \
    $scapy_tar \
    root@127.0.0.1:/tmp/
puts "Source copied"

# ---- Run the RTNetlink live tests inside the VM ----
puts "Running RTNetlink live tests inside VM..."
set test_status [catch {
    exec ssh \
        -p $ssh_port \
        -i $ssh_key \
        -o StrictHostKeyChecking=no \
        -o LogLevel=ERROR \
        root@127.0.0.1 \
        "cd /tmp && tar xzf scapy-src.tar.gz && PYTHONPATH=/tmp python3 scapy/tools/UTscapy.py -t test/vm/rtnetlink_live.uts -k vm"
} test_output]

# Print test output (captured from SSH stdout)
puts $test_output

# ---- Shut the VM down gracefully ----
send "poweroff\r"
expect {
    "Power down" { }
    eof          { }
    timeout      { }
}
wait

# ---- Report result ----
if {$test_status != 0} {
    puts stderr "ERROR: RTNetlink VM tests FAILED"
    exit 1
}
puts "=== RTNetlink VM tests PASSED ==="
exit 0
EXPECT_EOF
