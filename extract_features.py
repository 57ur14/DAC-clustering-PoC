#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import hashlib
import os
import pickle

import filetype
import pefile
import pyhash
import tlsh

import peicoex
import unpacking

config = configparser.ConfigParser()
config.read('config.ini')
DEBUG = config.getboolean('clustering', 'debug')
DEBUG_FILECOUNT = config.getint('clustering', 'debug_filecount')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')

xxhasher = pyhash.xx_64()
base_directory = '/home/sturla/IJCNN_10000files/'

files = {}                  # Dictionary of of files
non_parsable_files = {}     # Dictionary of files that could not be parsed
incoming_files = set()      # Set of icoming files (identified by md5sum)

def analyse_file(fullfilepath, family=None, unpacks_from=set()):
    """
    Analyse a pe-file at the given filepath, add to list of files and return sha256sum
    Can also specify the family the pe belongs to (if known) and the 
    sha256sum of the file that that unpacked the incoming file.

    If "family" is None, it means that the family is unknown.

    TODO: Document arguments and return value
    """

    with open(fullfilepath, 'rb') as filehandle:
        rawfile = filehandle.read()

        fileinfo = {
            'fullpath': fullfilepath,
            'md5': hashlib.md5(rawfile).hexdigest(),
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family,
            'suspicious': False,
            'unpacks_from': unpacks_from,
            'contained_pe_files': set(),
            'contained_resources': set(),
            'imphash': None,
            'icon_hash': None,
            'tlsh': tlsh.hash(rawfile),
            'tlsh_cluster': None,
            'final_cluster': None
        }

        # Use previously gathered information if a file with equal sha256sum already has been analysed
        if fileinfo['sha256'] in files.keys():
            files[fileinfo['sha256']]['unpacks_from'].add(fileinfo['sha256'])
            return fileinfo['sha256']

        try:
            pe = pefile.PE(data=rawfile)
        except Exception:
            non_parsable_files[fileinfo['sha256']] = fileinfo   # If the file cannot be parsed by pefile, 
            return None                                         # add to list of files that cannot be parsed
 
        pe.parse_data_directories()

        # Extract all features regardless of obfuscation
        fileinfo['icon_hash'] = get_icon_hash(pe)
        fileinfo['pefile_warnings'] = pe.get_warnings()
        fileinfo['imphash'] = pe.get_imphash()
        if fileinfo['imphash'] == '':
            fileinfo['imphash'] = None
        fileinfo['obfuscation'] = unpacking.detect_obfuscation(fullfilepath, pe, fileinfo['pefile_warnings'])
        if len(fileinfo['pefile_warnings']) != 0:       # Simple method of identifying if file seems suspicious
            fileinfo['suspicious'] = True               # TODO: Investigate peutils -> is_suspicious(pe) (function in peutils.py)

        if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            unpacked = unpacking.unpack_file(fullfilepath, fileinfo, pe)
            
            for unpacked_file in unpacked:              # For all unpacked files
                if filetype.guess_mime(unpacked_file) == 'application/x-msdownload':
                    # Check if the file is an "exe" (pe file) and analyse it if it is
                    analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=set([fileinfo['sha256']]))
                    if analysis_result != None:
                        fileinfo['contained_pe_files'].add(analysis_result)
                        continue
                # If the file is not a pe file or the pe file is corrupt, 
                # simply add a hash of the unpacked file to "contained resources"
                fileinfo['contained_resources'].add(os.path.basename(unpacked_file))

        files[fileinfo['sha256']] = fileinfo            # Add to list of files

        return fileinfo['sha256']                       # Return the sha256sum of the pe file
    return None                                         # Return None if the file could not be opened

def get_icon_hash(pefile_pe):
    """
    Retrieve a hash of the icon a Windows system would prefer to use.
    Returns None if no RT_GROUP_ICON was found or the icon could not be extracted properly.
    https://docs.microsoft.com/en-us/windows/win32/menurc/about-icons#icon-display
    TODO: Beskriv hvorfor xxhash64 brukes: https://aras-p.info/blog/2016/08/02/Hash-Functions-all-the-way-down/
    """
    extract = peicoex.ExtractIcon(pefile_pe=pefile_pe)
    raw = extract.get_raw_windows_preferred_icon()
    if raw != None:
        return xxhasher(raw)
    else:
        return None

def load_historic_data():
    """
    Load historic data
    Retrieves a list of the files from a specified txt file.
    Sends all files to the "analyse_file" function that extracts features and clusters files.
    """
    
    with open('/home/sturla/poc/files.txt', 'r') as trainfilesfile:
        train = trainfilesfile.read().splitlines()
        
        num_files = len(train)

        i = 1
        for trainFile in train:
            path = base_directory + trainFile
            fam, md5 = trainFile.split('/')

            incoming_files.add(md5)

            analyse_file(path, family=fam)
            
            
            if PRINT_PROGRESS:
                print("Analysed " + str(i) + " of " + str(num_files) + " files.")
            
            if DEBUG == True and i == DEBUG_FILECOUNT:
                break       # Only process a certain number of files if debugging
            i += 1
    

load_historic_data()

# Output results to pickles to allow further processing
with open('pickles/files.pkl', 'wb') as picklefile:
    pickle.dump(files, picklefile)
with open('pickles/incoming_files.pkl', 'wb') as picklefile:
    pickle.dump(incoming_files, picklefile)
with open('pickles/non_parsable_files.pkl', 'wb') as picklefile:
    pickle.dump(non_parsable_files, picklefile)