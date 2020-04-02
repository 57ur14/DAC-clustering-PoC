# -*- coding: utf-8 -*-

# External dependencies:
# * pefile
# * requests
# * diec - https://github.com/horsicq/Detect-It-Easy (must be installed and added to path manually)
# * clamav
# * libclamunrar9
# * upx

import configparser
import hashlib
import os
import shutil
import subprocess
import sys
import time
import tempfile

import peutils
import requests

config = configparser.ConfigParser()
config.read('config.ini')
unpack_directory = config.get('clustering', 'unpacking_base_directory')

# Create necessary directory if it does not exist
if not os.path.exists(unpack_directory):
    os.makedirs(unpack_directory)

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
    Run Detect It Easy Console on a file specified by a filepath and return values in a dictionary.
    """
    info = {}
    try:
        diec_process = subprocess.run(["diec", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as err:
        print(err) # TODO: Handle error
    except OSError as err:
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return get_diec_output(filepath)
    else:
        diec_output = diec_process.stdout.decode('utf-8')
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

def unpack_file(filepath, original_sha256):
    """
    Attempt to unpack a file that has been identified to be packed.
    Returns a list of unpacked files. In most cases an empty list or a list with a single filepath.
    """

    tmpfile_object = tempfile.TemporaryDirectory()
    tmpdir = tmpfile_object.name

    # Attempt static unpacking with ClamAV. Return unpacked files.
    return clam_unpack(filepath, tmpdir)

def clam_unpack(filepath, tmpdir=None):
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

    Dependencies (can be installed from apt repositories on Ubuntu):
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
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return clam_unpack(filepath, tmpdir)
    else:
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for filename in files:
                oldpath, newfilename = rename_to_sha256(os.path.join(root, filename))
                newpath = os.path.join(unpack_directory, newfilename)
                shutil.move(oldpath, newpath)
                unpacked.append(newpath)
            for dirname in dirs:
                os.rmdir(os.path.join(root, dirname))
        return unpacked

def rename_to_sha256(filepath):
    """
    Rename a file specified by a path to the sha256sum of the files and return the new path
    """
    with open(filepath, 'rb') as filehandle:
        rawfile = filehandle.read()
        directory = os.path.dirname(filepath)
        sha256sum = hashlib.sha256(rawfile).hexdigest()
        newpath = directory + '/' + sha256sum
        if filepath != newpath:             # Only rename if it is not already named as the sha256sum
            shutil.move(filepath, newpath)  # Rename file to the sha256sum
        return newpath, sha256sum       # Return the new path of the file and the sha256-sum (filename)
    return None, None                       # Return None if the file could not be opened
