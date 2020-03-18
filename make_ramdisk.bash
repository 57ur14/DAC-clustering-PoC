#!/bin/bash
sudo mkdir /mnt/ramdisk
sudo mount -t tmpfs -o rw,size=512M tmpfs /mnt/ramdisk
