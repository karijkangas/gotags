#!/bin/bash

DISK_FILE=debian-11.qcow2
CORE_COUNT=4
MEMORY_SIZE=4G

EFI_FIRM="$(dirname $(which qemu-img))/../share/qemu/edk2-aarch64-code.fd"
OVMF_VARS=debian-11_ovmf_vars.fd

echo "starting"

qemu-system-aarch64 \
  -machine virt,accel=hvf,highmem=off \
  -cpu cortex-a72 -smp $CORE_COUNT -m $MEMORY_SIZE \
  -device qemu-xhci,id=usb-bus \
  -device usb-tablet,bus=usb-bus.0 \
  -device usb-mouse,bus=usb-bus.0 \
  -device usb-kbd,bus=usb-bus.0 \
  -device virtio-gpu-pci \
  -display default,show-cursor=on \
  -drive format=raw,file=$EFI_FIRM,if=pflash,readonly=on \
  -drive format=raw,file=$OVMF_VARS,if=pflash \
  -device nvme,drive=drive0,serial=drive0,bootindex=0 \
  -drive if=none,media=disk,id=drive0,format=qcow2,file=$DISK_FILE \
  -net nic,model=virtio \
  -net user,hostfwd=tcp::8022-:22,hostfwd=tcp::8000-:8000 \
  -nographic
