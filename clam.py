#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Clam dependencies:
# clamav
# libclamunrar9

# Supported packers:
# Aspack (2.12)
# UPX (all versions)
# FSG (1.3, 1.31, 1.33, 2.0)
# Petite (2.x)
# PeSpin (1.1)
# NsPack
# wwpack32 (1.20)
# MEW
# Upack
# Y0da Cryptor (1.3)

# Confirmed:
# Upack (noen)
# NsPack (noen)
# FSG
# AsPack (noen)


# Remove all signatures from /var/lib/clamav
# add "pass.yar" to /var/lib/clamav with the content:
#
# rule pass
# {
#    condition:
#       false
# }

import os
import subprocess

clam_tmpdir = '/tmp/clamscan'
clam_supported_packers = [
    'aspack',
    'upx',
    'fsg',
    'petite',
    'pespin',
    'nspack',
    'wwpack',
    'mew',
    'upack',
    'y0da protector'
]

try:
    os.mkdir(clam_tmpdir)
except FileExistsError:
    pass

def clam_unpack(filepath):
    try:
        clamscan_process = subprocess.run([
                'clamscan', 
                '--debug', 
                '--leave-temps=yes', 
                '--tempdir='+clam_tmpdir, 
                '--no-summary',
                '--bytecode=no',
                '--scan-mail=no',
                '--phishing-sigs=no',
                '--phishing-scan-urls=no',
                '--heuristic-alerts=no',
                '--scan-pe=yes', 
                '--scan-elf=no',
                '--scan-ole2=no',
                '--scan-pdf=no',
                '--scan-swf=no',
                '--scan-html=no',
                '--scan-xmldocs=no',
                '--scan-hwp3=no',
                '--max-scantime=300',
                filepath
            ], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            check=True,
            timeout=5
        )
    except subprocess.CalledProcessError as err:
        print(err) # TODO: Handle error
    
    content = os.listdir(clam_tmpdir)
    if len(content):
        if len(content) > 1:
            pass # TODO: Handle multiple files
        else:
            pass # TODO: Handle one result
    else:               # Nothing was unpacked
        return None