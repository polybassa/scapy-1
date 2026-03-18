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
#   qemu-system-x86_64, qemu-img, genisoimage, ssh, scp, wget
#
# openssh is pre-installed in the Alpine cloud image, so no in-VM package
# download is needed for SSH.  python3 and iproute2 are still fetched via
# apk inside the VM (internet access is required for those two packages).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALPINE_VERSION="3.23.3"
ALPINE_MINOR="${ALPINE_VERSION%.*}"           # e.g.  3.23

# Alpine publishes pre-installed cloud/nocloud QCOW2 images that include
# openssh out of the box, so SSH is available without any in-VM apk install.
ALPINE_CLOUD_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MINOR}/releases/cloud/nocloud/alpine-virt-${ALPINE_VERSION}-x86_64.qcow2"

ALPINE_CLOUD_IMG="/tmp/alpine-virt-${ALPINE_VERSION}-cloud.qcow2"
VM_DISK="/tmp/alpine-vm.qcow2"
SEED_ISO="/tmp/cloud-seed.iso"
SSH_PORT="2222"
SSH_KEY="/tmp/vm_ed25519_key"
SCAPY_TAR="/tmp/scapy-src.tar.gz"

# Absolute path to the repo root (two directories up from this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Phase 1: Download Alpine Linux cloud QCOW2 image
# ---------------------------------------------------------------------------
# The cloud image ships with openssh pre-installed, so SSH is ready without
# any in-VM package download — even when the VM has no internet access.
echo "=== Downloading Alpine Linux ${ALPINE_VERSION} cloud image ==="
if [ ! -f "${ALPINE_CLOUD_IMG}" ]; then
    wget --quiet --show-progress --tries=3 \
        -O "${ALPINE_CLOUD_IMG}" "${ALPINE_CLOUD_URL}" || {
        echo "ERROR: Failed to download Alpine Linux cloud image from ${ALPINE_CLOUD_URL}"
        exit 1
    }
fi
echo "Cloud image ready: $(du -sh "${ALPINE_CLOUD_IMG}" | cut -f1)"

# ---------------------------------------------------------------------------
# Phase 2: Create VM disk as a QCOW2 overlay on the cloud base image
# ---------------------------------------------------------------------------
echo "=== Creating VM disk overlay ==="
qemu-img create -f qcow2 -b "${ALPINE_CLOUD_IMG}" -F qcow2 "${VM_DISK}" -q

# ---------------------------------------------------------------------------
# Phase 3: Generate SSH key for VM access
# ---------------------------------------------------------------------------
echo "=== Generating SSH key pair ==="
rm -f "${SSH_KEY}" "${SSH_KEY}.pub"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q
SSH_PUBKEY="$(cat "${SSH_KEY}.pub")"

# ---------------------------------------------------------------------------
# Phase 4: Create cloud-init nocloud seed ISO for SSH key injection
# ---------------------------------------------------------------------------
# tiny-cloud (Alpine's cloud-init) reads a volume labelled "cidata" and
# injects the listed SSH public keys into /root/.ssh/authorized_keys on the
# first boot — no internet access required for this step.
echo "=== Creating cloud-init seed ISO ==="
SEED_DIR="/tmp/cloud-seed-files"
rm -rf "${SEED_DIR}"
mkdir -p "${SEED_DIR}"

cat > "${SEED_DIR}/meta-data" <<EOF
instance-id: scapy-vm-01
local-hostname: alpine-vm
EOF

{
    echo "#cloud-config"
    echo "ssh_authorized_keys:"
    printf "  - %s\n" "${SSH_PUBKEY}"
} > "${SEED_DIR}/user-data"

genisoimage -quiet \
    -output "${SEED_ISO}" \
    -volid cidata \
    -joliet \
    -rock \
    "${SEED_DIR}/user-data" \
    "${SEED_DIR}/meta-data"

# ---------------------------------------------------------------------------
# Phase 5: Package the scapy source for transfer into the VM
# ---------------------------------------------------------------------------
echo "=== Packaging Scapy source ==="
tar czf "${SCAPY_TAR}" \
    -C "${REPO_ROOT}" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    scapy/ test/

# ---------------------------------------------------------------------------
# Phase 6: Boot Alpine VM in the background
# ---------------------------------------------------------------------------
echo "=== Starting Alpine VM ==="
KVM_FLAGS=()
if [ -e /dev/kvm ]; then
    echo "KVM acceleration: enabled"
    KVM_FLAGS=(-enable-kvm)
else
    echo "KVM acceleration: not available (using TCG - slower)"
fi

qemu-system-x86_64 \
    -m 512M \
    -smp 2 \
    -drive "file=${VM_DISK},format=qcow2,if=virtio" \
    -cdrom "${SEED_ISO}" \
    -boot order=c \
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    "${KVM_FLAGS[@]}" \
    > /tmp/qemu-console.log 2>&1 &
QEMU_PID=$!
echo "QEMU PID: ${QEMU_PID}"

# ---------------------------------------------------------------------------
# Phase 7: Wait for SSH to become reachable
# ---------------------------------------------------------------------------
# openssh is already installed in the cloud image and tiny-cloud starts sshd
# after injecting the authorized key, so no console interaction is needed.
echo "=== Waiting for SSH to become reachable ==="
SSH_OPTS=(-p "${SSH_PORT}" -i "${SSH_KEY}"
          -o StrictHostKeyChecking=no
          -o ConnectTimeout=2
          -o LogLevel=ERROR)
SSH_READY=0
for i in $(seq 1 60); do
    if ssh "${SSH_OPTS[@]}" root@127.0.0.1 "echo SSH_OK" 2>/dev/null \
            | grep -q SSH_OK; then
        SSH_READY=1
        echo "SSH is reachable (attempt ${i})"
        break
    fi
    sleep 2
done

if [ "${SSH_READY}" -eq 0 ]; then
    echo "ERROR: SSH did not become reachable within 120 s"
    echo "=== QEMU console log ==="
    cat /tmp/qemu-console.log
    kill "${QEMU_PID}" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 8: Install remaining packages and prepare the VM
# ---------------------------------------------------------------------------
# openssh is already present; only python3 and iproute2 need to be fetched.
echo "=== Installing packages ==="
ssh "${SSH_OPTS[@]}" root@127.0.0.1 bash <<REMOTE
set -euo pipefail
printf '%s\n%s\n' \
    'https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MINOR}/main' \
    'https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MINOR}/community' \
    > /etc/apk/repositories
apk update
apk add python3 iproute2
REMOTE

# Load dummy kernel module (for test interfaces)
ssh "${SSH_OPTS[@]}" root@127.0.0.1 "modprobe dummy 2>/dev/null || true"

# ---------------------------------------------------------------------------
# Phase 9: Copy Scapy source and run tests
# ---------------------------------------------------------------------------
echo "=== Copying Scapy source to VM ==="
scp -P "${SSH_PORT}" -i "${SSH_KEY}" \
    -o StrictHostKeyChecking=no \
    -o LogLevel=ERROR \
    "${SCAPY_TAR}" \
    root@127.0.0.1:/tmp/

echo "=== Running RTNetlink live tests inside VM ==="
ssh "${SSH_OPTS[@]}" root@127.0.0.1 \
    "cd /tmp && tar xzf scapy-src.tar.gz && \
     PYTHONPATH=/tmp python3 scapy/tools/UTscapy.py \
         -t test/vm/rtnetlink_live.uts -k vm"
TEST_RC=$?

# ---------------------------------------------------------------------------
# Phase 10: Shut the VM down gracefully
# ---------------------------------------------------------------------------
echo "=== Shutting down VM ==="
ssh "${SSH_OPTS[@]}" root@127.0.0.1 "poweroff" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true

if [ "${TEST_RC}" -ne 0 ]; then
    echo "ERROR: RTNetlink VM tests FAILED"
    exit 1
fi
echo "=== RTNetlink VM tests PASSED ==="
