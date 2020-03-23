#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# External dependencies:
# filetype:                     pip3 install filetype
# pefile:                       pip3 install pefile
# xxhash:                       pip3 install xxhash
# tlsh:                         https://github.com/trendmicro/tlsh
# pefile-extract-icon:          https://github.com/ntnu-rgb/pefile-extract-icon

import argparse
import configparser
import hashlib
import os
import pickle
import queue
import subprocess
from multiprocessing.managers import BaseManager

import filetype
import pefile
import tlsh
import xxhash

import extract_icon
import unpacking

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
QUEUE_MANAGER_IP = config.get('queue_manager', 'ip')
QUEUE_MANAGER_PORT = config.getint('queue_manager', 'port')
QUEUE_MANAGER_KEY = config.get('queue_manager', 'key').encode('utf-8')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')

# Connect to queue
class QueueManager(BaseManager):
    pass
QueueManager.register('get_queue')
manager = QueueManager(address=(QUEUE_MANAGER_IP, QUEUE_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
try:
    manager.connect()
except:
    print("Cannot connect to queue manager. Please check the configuration.")
    raise SystemExit
queue = manager.get_queue()

def main():
    """
    Parse arguments and begin extraction of file
    """
    parser = argparse.ArgumentParser(description='Process a file; Extract features and send to clustering.')
    parser.add_argument('-P', '--path', help='Path to a single file that should be processed.')
    parser.add_argument('-F', '--family', help='Malware family the single file belongs to (optional)')
    parser.add_argument('-L', '--list', help='Path to a file containing paths to files on separate lines')
    parser.add_argument('-C', '--combined-list', help='Path to a file where each line consists of <path> <family>. Path must not contain any spaces.')
    args = parser.parse_args()
    
    if args.path is not None:
        # Process single specified file
        analyse_file(args.path, family=args.family, incoming=True)
    elif args.list is not None:
        # Load paths from file and process files
        with open(args.list, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                analyse_file(line, incoming=True)
    elif args.combined_list is not None:
        # Load paths and families from file and process the files
        with open(args.combined_list, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                path, fam = line.split(' ')
                analyse_file(path, family=fam, incoming=True)
    else:
        # Print help if no arguments were specified
        print("At least one of the following combinations must be supplied: (-P <path> [-F <family>]) | -L <path to list> | -C <path to combined-list>")
        parser.print_help()

def analyse_file(fullfilepath, family=None, unpacks_from=set(), incoming=False, unpack_chain=None):
    """
    Analyse a pe-file at the given filepath, add to list of files and return sha256sum
    Can also specify the family the pe belongs to (if known) and the 
    sha256sum of the file that that unpacked the incoming file.

    If "family" is None, it means that the family is unknown.
    If "incoming" is True, the file is added to the "incoming files" set.
    """

    if PRINT_PROGRESS == True:
        if family is None:
            print('Processing file ' + fullfilepath)
        else:
            print('Processing file ' + fullfilepath + ' (' + family + ')')

    with open(fullfilepath, 'rb') as filehandle:
        rawfile = filehandle.read()

        fileinfo = {
            'fullpath': fullfilepath,
            'md5': hashlib.md5(rawfile).hexdigest(),
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family,
            'incoming': incoming,
            'suspicious': False,
            'unpacks_from': unpacks_from,
            'contained_pe_files': set(),
            'contained_resources': set(),
            'imphash': None,
            'icon_hash': None,
            'tlsh': None,
            'tlsh_cluster': None,
            'union_cluster': None
        }

        if incoming == False:
            if unpack_chain is None:
                # If first file in unpacking chain
                # Create new unpacking chain with checksum of parent
                unpack_chain = unpacks_from.copy()
            elif fileinfo['sha256'] in unpack_chain:
                # Abort if this the unpacking is looping
                return None
            # Add checksum of this file to unpacking chain
            unpack_chain.add(fileinfo['sha256'])
        try:
            pe = pefile.PE(data=rawfile)
        except Exception:
            # TODO: Find alternative solution
            #non_parsable_files[fileinfo['sha256']] = fileinfo   # If the file cannot be parsed by pefile, 
            return None                                         # add to list of files that cannot be parsed

        pe.parse_data_directories()

        # Extract all features regardless of obfuscation
        fileinfo['icon_hash'] = get_icon_hash(pe)
        fileinfo['pefile_warnings'] = pe.get_warnings()
        
        fileinfo['obfuscation'] = unpacking.detect_obfuscation(fullfilepath, pe, fileinfo['pefile_warnings'])
        if len(fileinfo['pefile_warnings']) != 0:       # Simple method of identifying if file seems suspicious
            fileinfo['suspicious'] = True               # TODO: Investigate peutils -> is_suspicious(pe) (function in peutils.py)

        if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            # Attempt to unpack the packed file
            unpacked = unpacking.unpack_file(fullfilepath, fileinfo, pe)
            
            for unpacked_file in unpacked:              # For all unpacked files
                if filetype.guess_mime(unpacked_file) == 'application/x-msdownload':
                    # Check if the file is an "exe" (pe file) and analyse it if it is
                    analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=set([fileinfo['sha256']]), unpack_chain=unpack_chain)
                    if analysis_result is not None:
                        fileinfo['contained_pe_files'].add(analysis_result)
                else:
                    # If the file is not a pe file or the pe file is corrupt, 
                    # simply add a hash of the unpacked file to "contained resources"
                    fileinfo['contained_resources'].add(os.path.basename(unpacked_file))
            
            if CLUSTER_PACKED_FILES == True:
                # If one should extract certain features without regard
                # to the file being packed, do so
                fileinfo['imphash'] = get_imphash(pe)
                fileinfo['tlsh'] = tlsh.hash(rawfile)
        else:
            # Extract imphash and tlsh if file is not packed
            fileinfo['imphash'] = get_imphash(pe)
            fileinfo['tlsh'] = tlsh.hash(rawfile)


        queue.put(fileinfo)                             # Send to clustering by adding to queue

        return fileinfo['sha256']                       # Return True on success
    return None                                         # Return False on failure

def get_icon_hash(pefile_pe):
    """
    Retrieve a hash of the icon a Windows system would prefer to use.
    Returns None if no RT_GROUP_ICON was found or the icon could not be extracted properly.
    https://docs.microsoft.com/en-us/windows/win32/menurc/about-icons#icon-display
    TODO: Beskriv hvorfor xxhash64 brukes: https://aras-p.info/blog/2016/08/02/Hash-Functions-all-the-way-down/
    """
    extract = extract_icon.ExtractIcon(pefile_pe=pefile_pe)
    raw = extract.get_raw_windows_preferred_icon()
    if raw is not None:
        return xxhash.xxh64_digest(raw)
    else:
        return None

def get_imphash(pefile_pe):
    """
    Retrieve the imphash of a PE file.
    Returns None if imphash could not be extracted.
    """
    imphash = pefile_pe.get_imphash()
    if imphash == '':
        return None
    else:
        return imphash


main() # Run main after parsing file