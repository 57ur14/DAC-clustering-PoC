# -*- coding: utf-8 -*-

import os
import shutil
import sys
import threading
from unipacker.core import Sample
from unipacker.io_handler import IOHandler
import subprocess
import hashlib
import requests

unpack_directory = '/home/sturla/unpacked/'
static_unpack_directory = unpack_directory + 'static/'
generic_unpack_directory = unpack_directory + 'generic/'

tmpdir = '/tmp/unpacking/'
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

unipack_supported_packers = [
    'aspack',
    'fsg',
    'mew',
    'mpress',
    'petite',
    'upx',
    'yzpack'
]

try:
    os.mkdir(tmpdir)       # Create a new temporary directory
except FileExistsError:
    pass

def unpack_file(filepath, info, pefile_pe):
    """
    Attempt to unpack a file that has been identified to be packed.
    Returns a list of unpacked files. In most cases an empty list or a list with a single filepath.
    """

    unpacked = []
    if 'protector' in info and info['protector'] == 'themida':  # Skip the file if it cannot be unpacked
        return unpacked                                         # (protected by virtualizers and such)

    # is_x86 = pefile_pe.FILE_HEADER.Machine == 0x14c # 0x14c -> Intel 386 or later processors and compatible processors (32-bit PE)
    
    if info['type'] == 'packed':
        if 'upx' in info['packer']:
            unpacked = unpack_upx(filepath)
        
    if len(unpacked) == 0 and (('packer' in info and info['packer'] in clam_supported_packers) or ('protector' in info and info['protector'] in clam_supported_packers)):
        unpacked = clam_unpack(filepath)    # Attempt static unpacking with ClamAV

    if len(unpacked) == 0 and 'packer' in info and info['packer'] in unipack_supported_packers:
        unpacked = unipack(filepath)        # Attempt to generic unpacking with unipacker

    return unpacked                         # Return the unpacked files


def unpack_upx(filepath):
    """
    Unpack with UPX

    Dependencies (can be installed from apt repositories in Ubuntu):
    * upx
    """
    filename = filepath.split('/')[-1]
    tmp_path = os.path.join(tmpdir, filename)
    shutil.copyfile(filepath, tmp_path)     # Copy file to unpack directory
    try:
        subprocess.run(["upx", "-d", tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError:
        os.remove(tmp_path)                 # Delete copy if it could not be unpacked
        return []                           # Return an empty list if the file could not be unpacked
    else:
        newpath = os.path.join(static_unpack_directory, filename)
        shutil.move(tmp_path, newpath)      # Move file to directory of unpacked files
        return [rename_to_sha256(newpath)]  # Return new path of the unpacked file if successful

def unipack(filepath):
    """
    Attempt to unpack a file at a given path with unipack.
    Emulates execution over a maximum of 5 seconds in an attempt to unpack PE-files that are packed with "simple" packers.
    Returns a list that can either be empty (could not unpack) or contain a filepath to a file that was unpacked.
    Dependencies:
    * unattended-unipacker [https://github.com/ntnu-rgb/unattended-unipacker]
    """
    try:
        subprocess.run(
            ["unipacker", '-d', generic_unpack_directory, filepath], 
            stdin = subprocess.PIPE, 
            stdout = subprocess.PIPE, 
            stderr = subprocess.PIPE, 
            check=True, 
            timeout=5
        )                       # If it hasn't finished in 5 seconds, it will likely never succeed
    except subprocess.TimeoutExpired:
        print("Timeout reached for unipacker")
        return []               # Timeout reached, skip file
    except subprocess.CalledProcessError:
        return []               # unipacker crashed, skip file
    else:
        return [rename_to_sha256(generic_unpack_directory + 'unpacked_' + filepath.split('/')[-1])]

def arancino_unpack(filepath):
    """
    url = 'http://henriette.rgb.moe/unpack.php'
    with open(filepath, 'rb') as f:
        r = requests.post(url, files={'upload': f})
        print(r)
        raise SystemExit
        return r.text
    print("Generic unpacking is WIP")
    return None
    """
    return None # TODO: Skipping unpacking since no generic unpacking seems to be successful as of now

def rename_to_sha256(filepath):
    """
    Rename a file specified by a path to the sha256sum of the files and return the new path
    """
    with open(filepath, 'rb') as filehandle:
        rawfile = filehandle.read()
        directory = os.path.dirname(filepath)
        newpath = directory + '/' + hashlib.sha256(rawfile).hexdigest()
        if filepath != newpath:
            shutil.move(filepath, newpath) # Rename file to the sha256sum
        # Should not matter if "move" overwrites a previously unpacked file 
        # since they would have to be identical
        return newpath                  # Return the new path of the file
    return None                         # Return None if the file could not be opened

def clam_unpack(filepath):
    """
    Attempt to unpack the malware statically with ClamAV.
    Returns a list that can either be empty or contain paths to files unpacked from the file at the specified path.

    Packers supported by ClamAV [https://www.clamav.net/documents/libclamav]:
    * Aspack (2.12)
    * UPX (all versions)
    * FSG (1.3, 1.31, 1.33, 2.0)
    * Petite (2.x)
    * PeSpin (1.1)
    * NsPack
    * wwpack32 (1.20)
    * MEW
    * Upack
    * Y0da Cryptor (1.3)

    Dependencies (can be installed from apt repositories on Ubuntu):
    * clamav
    * libclamunrar9

    Loading and comparing all signatures typically requires 20 seconds extra runtime.
    To ensure fast execution, remove all signatures and disable signature updates.:
    * Disable the freshclam service: ``service clamav-freshclam stop && systemctl disable clamav-freshclam``
    * Remove all signature files from /var/lib/clamav
    * Add a file "pass.yar" to /var/lib/clamav with the following content:
        rule pass
        {
            condition:
                false
        }
    """
    unpacked = []

    try:
        clamscan_process = subprocess.run([
                'clamscan', 
                '--debug', 
                '--leave-temps=yes', 
                '--tempdir='+tmpdir, 
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
                filepath
            ], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            check=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        print('Timeout reached for ClamAV')
        return unpacked             # Timeout reached, return empty list
    except subprocess.CalledProcessError:
        return unpacked             # clamscan crashed, return empty list
    else:
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for filename in files:
                oldpath = rename_to_sha256(os.path.join(root, filename))
                newpath = os.path.join(static_unpack_directory, oldpath.split('/')[-1])
                shutil.move(oldpath, newpath)
                unpacked.append(newpath)
            for dirname in dirs:
                os.rmdir(os.path.join(root, dirname))
        return unpacked