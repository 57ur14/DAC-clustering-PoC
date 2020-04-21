# -*- coding: utf-8 -*-
"""
unpacking - a module for detecting packers and unpacking packed files

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae

External dependencies:
* pefile:           pip3 install pefile
* diec:             Manual installation: https://github.com/horsicq/Detect-It-Easy
* clamav:           apt-get install clamav
* libclamunrar9:    apt-get install libclamunrar9
"""

import configparser
import hashlib
import os
import shutil
import subprocess
import sys
import time

import peutils

config = configparser.ConfigParser()
config.read('config.ini')
STORE_UNPACKED = config.getboolean('unpacking', 'store_unpacked')
if STORE_UNPACKED:
    UNPACKED_DIRECTORY = config.get('unpacking', 'directory')

# Create necessary directory if it does not exist
if STORE_UNPACKED and not os.path.exists(UNPACKED_DIRECTORY):
    os.makedirs(UNPACKED_DIRECTORY)

def detect_obfuscation_by_diec(filepath):
    """
    Detect obfuscaton with DetectItEasy
    """
    diec_output = get_diec_output(filepath)
    if 'protector' in diec_output:      # If it is protected, overwrite "type".
        return {'type': 'protected', 'protector': diec_output['protector']}
    elif 'packer' in diec_output:
        return {'type': 'packed', 'packer': diec_output['packer']}
    return None

def get_diec_output(filepath):
    """
    Run Detect It Easy Console on a file specified by a filepath 
    and return values in a dictionary.
    
    Detect It Easy console version (diec) must be installed manually
    and "diec" must be included in $PATH.
    """
    info = {}
    try:
        diec_process = subprocess.run(["diec", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as err:
        print(err) # TODO: Handle error
    except OSError as err:
        # Potentially out of memory or encountered other error.
        # Print error message and retry later.
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return get_diec_output(filepath)
    else:
        try:
            diec_output = diec_process.stdout.decode('utf-8')
        except UnicodeDecodeError:
            diec_output = ''
        for line in diec_output.splitlines():
            if line[0:12] == 'PE: packer: ':
                info['packer'] = line[12:]
            elif line[0:15] == 'PE: protector: ':
                info['protector'] = line[15:]
            elif line[0:12] == 'PE: linker: ':
                info['linker'] = line[12:]
            elif line[0:14] == 'PE: compiler: ':
                info['compiler'] = line[14:]
            elif line[0:13] == 'PE: library: ':
                info['library'] = line[13:]
            elif line[0:15] == 'PE: installer: ':
                info['installer'] = line[15:]
            elif line[0:13] == 'PE: overlay: ':
                info['overlay'] = line[13:]
            elif line[0:9] == 'PE: sfx: ':
                info['sfx'] = line[9:]
            elif line[0:13] == 'PE: archive: ':
                info['archive'] = line[13:]
            elif line[0:12] == 'PE: joiner: ':
                info['joiner'] = line[12:]
    return info

def unpack_file(filepath, tmpdir):
    """
    Attempt to unpack file.
    filepath is the path to the file that should be attempted unpacked.
    tmpdir is a path to a temporary directory unique to this thread where
    the thread will attempt to unpack files to.
    Returns a list of unpacked files or an empty list.
    """

    # Other unpacking tools have been removed due to
    # lacking reliability and usefulness of the tools.

    # If multiple unpacking tools are to be used here, 
    # subdirectories below tmpdir should be created for each
    # tool to avoid tools overwriting output of each other.

    # Attempt static unpacking with ClamAV. Return unpacked files.
    return clam_unpack(filepath, tmpdir)

def clam_unpack(filepath, tmpdir):
    """
    Attempt to unpack the malware statically with ClamAV.
    Returns a list that can either be empty or contain paths to files unpacked from the file at the specified path.

    Packers supported by ClamAV (https://www.clamav.net/documents/libclamav):
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

    Dependencies (can be installed from apt on Ubuntu):
    * clamav
    * libclamunrar9

    Loading and comparing all signatures typically requires 20 seconds extra runtime.
    To ensure fast execution, remove all signatures and disable signature updates.:
    * Disable the freshclam service: ``service clamav-freshclam stop && systemctl disable clamav-freshclam``
    * Remove all signature files from /var/lib/clamav/: ``rm -r /var/lib/clamav/*``
    * Add the new file /var/lib/clamav/pass.yar with the following content:
        rule pass
        {
            condition:
                false
        }
    """
    unpacked = []

    try:
        subprocess.run([
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
        return unpacked             # Timeout reached, return empty list
    except subprocess.CalledProcessError:
        return unpacked             # clamscan crashed, return empty list
    except OSError as err:
        # Potentially out of memory or encountered other error.
        # Print error message and retry later.
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return clam_unpack(filepath, tmpdir)
    else:
        for root, _, files in os.walk(tmpdir, topdown=False):
            for filename in files:
                if STORE_UNPACKED:
                    # Move file to permanent storage if 
                    # unpacked files should be stored.
                    oldpath, newfilename = rename_to_sha256(os.path.join(root, filename))
                    newpath = os.path.join(UNPACKED_DIRECTORY, newfilename)
                    shutil.move(oldpath, newpath)
                else:
                    newpath = os.path.join(root, filename)
                unpacked.append(newpath)
        return unpacked

def rename_to_sha256(filepath):
    """
    Rename a file specified by a path to the sha256sum 
    of the files and return the new path.
    Returns the new path and the sha256sum of the file
    """
    with open(filepath, 'rb') as filehandle:
        rawfile = filehandle.read()
        directory = os.path.dirname(filepath)
        sha256sum = hashlib.sha256(rawfile).hexdigest()
        newpath = os.path.join(directory, sha256sum)
        if filepath != newpath:             # Only rename if it is not already named as the sha256sum
            shutil.move(filepath, newpath)  # Rename file to the sha256sum
        return newpath, sha256sum           # Return the new path of the file and the sha256sum (filename)
    return None, None                       # Return None if the file could not be opened
