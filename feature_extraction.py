# -*- coding: utf-8 -*-
"""
clustering - a module for extracting features from PE executables

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae

External dependencies:
* filetype:             pip3 install filetype
* pefile:               pip3 install pefile
* tlsh:                 https://github.com/trendmicro/tlsh
* pefile-extract-icon:  https://github.com/ntnu-rgb/pefile-extract-icon
"""

import configparser
import hashlib
import os
import shutil
import tempfile

import filetype
import pefile
import tlsh

import extract_icon
import unpacking

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('general', 'print_progress')
EXTRACT_ALL_FEATURES = config.getboolean('feature_extraction', 'extract_all_features')
ATTEMPT_UNPACK_ALL_FILES = config.getboolean('feature_extraction', 'attempt_unpack_all_files')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_CONTAINED_PE = config.getboolean('clustering', 'cluster_with_contained_pe')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')
CLUSTER_WITH_VHASH = config.getboolean('clustering', 'cluster_with_vhash')

if CLUSTER_WITH_VHASH:
    # Load sha2vhash dict from pickle if CLUSTER_WITH_VHASH is True
    import pickle
    with open('pickles/sha2vhash.pkl', 'rb') as picklefile:
        SHA2VHASH = pickle.load(picklefile)

def analyse_file(fullfilepath, unpacks_from=set(), unpacking_set=set(), incoming=False, family=None, training=False):
    """
    Analyse a pe-file at the given filepath and return a "fileinfo" dictionary
    containing the features of the file.

    Parameters:
    - fullfilepath String: The full path to the file that should be analysed.
    - unpacks_from set: A set containing the sha256 checksum of thefile this file was
    - unpacked from (or an empty set if this was not unpacked from another file)
    - unpacking_set Set: A set of sha256 checkums of the files previously unpacked in the "unpacking chain". Allows detection of loops.
    - incoming Boolean: Indicates if the file was really incoming to feature extraction or just unpacked from another PE.
    - family String: The family (class) the file belongs to.
    - training Boolean: Indicates if the file is part of the "training" (training where the family should be known to the algorithm)
    """

    if PRINT_PROGRESS:
        if family is None:
            print('Extracting features from ' + fullfilepath)
        else:
            print('Extracting features from ' + fullfilepath + ' (' + family + ')')

    try:
        with open(fullfilepath, 'rb') as filehandle:
            rawfile = filehandle.read()
    except FileNotFoundError:
        return None
    else:
        fileinfo = {
            'fullpath': fullfilepath,
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family,
            'incoming': incoming,
            'training': training,
            'suspicious': False,
            'obfuscation': None,
            'pefile_warnings': [],
            'unpacks_from': unpacks_from,
            'contained_pe_files': set(),
            'unpacks_to_nonpacked_pe': False,
            'contained_pe_fileinfo': {},
            'contained_resources': set(),
            'imphash': None,
            'icon_hash': None,
            'tlsh': None,
            'tlsh_cluster': None,
            'fast_clustered': False,
            'slow_clustered': False,
            'given_label': None
        }

        if training:
            # If file is in training data set, set
            # the given label to the provided family name
            fileinfo['given_label'] = family

        if not incoming and fileinfo['sha256'] in unpacking_set:
            # Abort if file already is part of the 
            # unpacking chain to avoid infinite recursion.
            return None
        
        if CLUSTER_WITH_VHASH:
            fileinfo['vhash'] = SHA2VHASH.get(fileinfo['sha256'], None)
        
        # Add to unpacking chain to allow loop detection
        unpacking_set.add(fileinfo['sha256'])

        try:
            pe = pefile.PE(data=rawfile)
        except Exception:
            # If file cannot be parsed with pefile, 
            # extract basic file features and return.
            if incoming:
                if EXTRACT_ALL_FEATURES or CLUSTER_WITH_TLSH:
                    fileinfo['tlsh'] = tlsh.hash(rawfile)
                return fileinfo
            else:
                # If file was not incoming (was unpacked), 
                # return None (unsuccessful unpacking)
                return None

        pe.parse_data_directories()
        fileinfo['pefile_warnings'] = pe.get_warnings()
        if fileinfo['pefile_warnings']:
            # Simple method of identifying if file seems suspicious
            fileinfo['suspicious'] = True

        fileinfo['obfuscation'] = unpacking.detect_obfuscation_by_diec(fullfilepath)
        
        
        unpacked = []
        # If file is detected as being packed or one should attemp unpacking on all files
        if fileinfo['obfuscation'] is not None or ATTEMPT_UNPACK_ALL_FILES:
            # Create a temporary directory unique to this process
            # for unpacking contained files
            tmpdir = tempfile.mkdtemp(prefix='unpack-dir-')

            # Attempt to unpack the packed file regardless of detected obfuscation
            unpacked = unpacking.unpack_file(fullfilepath, tmpdir)
            for unpacked_file in unpacked:              # For all unpacked files
                    if (filetype.guess_mime(unpacked_file) == 'application/x-msdownload'
                            and (EXTRACT_ALL_FEATURES or CLUSTER_WITH_CONTAINED_PE)):
                        # Check if the file is an "exe" (pe file) and analyse it if so
                        analysis_result = analyse_file(unpacked_file, unpacks_from=set([fileinfo['sha256']]), unpacking_set=unpacking_set, family=family)
                        if analysis_result is not None:
                            # If file could be parsed by pefile
                            if (analysis_result['obfuscation'] is None
                                    or analysis_result['unpacks_to_nonpacked_pe']):
                                # If contained file is not packed or unpacks to a nonpacked file
                                # Mark this file as "unpacks to nonpacked pe"
                                fileinfo['unpacks_to_nonpacked_pe'] = True
                            fileinfo['contained_pe_files'].add(analysis_result['sha256'])
                            fileinfo['contained_pe_fileinfo'][analysis_result['sha256']] = analysis_result
                    elif EXTRACT_ALL_FEATURES or CLUSTER_WITH_RESOURCES:
                        # If the file is not a pe file or the pe file is corrupt, 
                        # simply add a hash of the unpacked file to "contained resources"
                        fileinfo['contained_resources'].add(os.path.basename(unpacked_file))
            # Delete temporary directory (with contents) 
            # when it is no longer needed.
            shutil.rmtree(tmpdir)
        
        if fileinfo['obfuscation'] is not None or unpacked:
            # If file seems to be packed
            if CLUSTER_PACKED_FILES:
                # If one should extract certain features without 
                # regard to the file being packed, do so.
                if EXTRACT_ALL_FEATURES or CLUSTER_WITH_IMPHASH:
                    fileinfo['imphash'] = get_imphash(pe)
                if EXTRACT_ALL_FEATURES or CLUSTER_WITH_TLSH:
                    fileinfo['tlsh'] = tlsh.hash(rawfile)
        else:
            # Extract imphash and tlsh if file is not packed
            # and config specifies to do so.
            if EXTRACT_ALL_FEATURES or CLUSTER_WITH_IMPHASH:
                fileinfo['imphash'] = get_imphash(pe)
            if EXTRACT_ALL_FEATURES or CLUSTER_WITH_TLSH:
                fileinfo['tlsh'] = tlsh.hash(rawfile)

        if EXTRACT_ALL_FEATURES or CLUSTER_WITH_ICON:
            # Extract icon if supposed to use icon
            fileinfo['icon_hash'] = get_icon_hash(pe)
        return fileinfo
    return None                               # Return None on failure

def get_icon_hash(pefile_pe):
    """
    Retrieve a hash of the icon a Windows system would prefer to use.
    Returns None if no RT_GROUP_ICON was found or the icon could not be extracted properly.
    Uses xxhash to retrieve a hash that is fast to calculate and with good uniqueness.
    """
    extract = extract_icon.ExtractIcon(pefile_pe=pefile_pe)
    raw = extract.get_raw_windows_preferred_icon()
    if raw is not None:
        return hashlib.sha256(raw).digest()
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
