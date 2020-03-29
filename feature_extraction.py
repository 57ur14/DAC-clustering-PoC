# -*- coding: utf-8 -*-

# External dependencies:
# filetype:                     pip3 install filetype
# pefile:                       pip3 install pefile
# xxhash:                       pip3 install xxhash
# tlsh:                         https://github.com/trendmicro/tlsh
# pefile-extract-icon:          https://github.com/ntnu-rgb/pefile-extract-icon

import configparser
import hashlib
import os

import filetype
import pefile
import tlsh
import xxhash

import extract_icon
import unpacking

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')
MAX_UNPACK_RECURSION = config.getint('feature_extraction', 'max_unpack_recursion')
DETECT_IT_EASY_ONLY = config.getint('feature_extraction', 'detect_it_easy_only')

def analyse_file(fullfilepath, family=None, training=False, unpacks_from=set(), incoming=False, unpack_chain=None):
    """
    Analyse a pe-file at the given filepath, add to list of files and return sha256sum
    Can also specify the family the pe belongs to (if known) and the 
    sha256sum of the file that that unpacked the incoming file.

    @family String / None: If it is None, it indicates that the family is unknown.
    @training Boolean: Indicates if the file is part of the "training" where the clustering should know the family
    @incoming Boolean: Indicates if the file was really incoming to feature 
        extraction or just unpacked from another PE.
    @unpack_chain set: Holds a list of "parent" PE-files that has been part of the unpacking. 
        Weird behavior in unipacker could otherwise result in infinite recursion.
    """

    if PRINT_PROGRESS:
        if family is None:
            print('Extracting features from ' + fullfilepath)
        else:
            print('Extracting features from ' + fullfilepath + ' (' + family + ')')

    with open(fullfilepath, 'rb') as filehandle:
        rawfile = filehandle.read()

        fileinfo = {
            'fullpath': fullfilepath,
            'md5': hashlib.md5(rawfile).hexdigest(),
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family,
            'incoming': incoming,
            'training': training,
            'suspicious': False,
            'obfuscation': None,
            'unpacks_from': unpacks_from,
            'contained_pe_files': set(),
            'unpacks_to_nonpacked_pe': False,
            'contained_pe_fileinfo': {},
            'contained_resources': set(),
            'imphash': None,
            'icon_hash': None,
            'tlsh': None,
            'tlsh_cluster': None,
            'union_cluster': None
        }

        if not incoming:
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
        fileinfo['pefile_warnings'] = pe.get_warnings()
        if fileinfo['pefile_warnings']:
            # Simple method of identifying if file seems suspicious
            # TODO: Investigate peutils -> is_suspicious(pe) (function in peutils.py)
            fileinfo['suspicious'] = True

        if DETECT_IT_EASY_ONLY:
            fileinfo['obfuscation'] = unpacking.detect_obfuscation_by_diec(fullfilepath)
        else:
            fileinfo['obfuscation'] = unpacking.detect_obfuscation(fullfilepath, pe, fileinfo['pefile_warnings'])

        if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            # Attempt to unpack the packed file
            unpacked = unpacking.unpack_file(fullfilepath, fileinfo, pe)
            
            for unpacked_file in unpacked:              # For all unpacked files
                if filetype.guess_mime(unpacked_file) == 'application/x-msdownload':
                    # Check if the file is an "exe" (pe file) and analyse it if so
                    if (unpack_chain is not None 
                            and len(unpack_chain) >= MAX_UNPACK_RECURSION):
                        # Skip unpacking if this file has been recursively unpacking 
                        # more than a specified number of times.
                        continue
                    analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=set([fileinfo['sha256']]), unpack_chain=unpack_chain)
                    if analysis_result is not None:
                        # If file could be parsed by pefile
                        # TODO: Could just change contained_pe_files to a dict and use .keys()
                        if (analysis_result['obfuscation']['type'] == 'none'
                                or analysis_result['unpacks_to_nonpacked_pe']):
                            # If contained file is not packed or unpacks to a nonpacked file
                            # Mark this file as "unpacks to nonpacked pe"
                            fileinfo['unpacks_to_nonpacked_pe'] = True
                        fileinfo['contained_pe_files'].add(analysis_result['sha256'])
                        fileinfo['contained_pe_fileinfo'][analysis_result['sha256']] = analysis_result
                else:
                    # If the file is not a pe file or the pe file is corrupt, 
                    # simply add a hash of the unpacked file to "contained resources"
                    fileinfo['contained_resources'].add(os.path.basename(unpacked_file))
            
            if CLUSTER_PACKED_FILES:
                # If one should extract certain features without regard
                # to the file being packed, do so
                fileinfo['imphash'] = get_imphash(pe)
                fileinfo['tlsh'] = tlsh.hash(rawfile)
        else:
            # Extract imphash and tlsh if file is not packed
            fileinfo['imphash'] = get_imphash(pe)
            fileinfo['tlsh'] = tlsh.hash(rawfile)
        # Extract icon regardless of whether the file is packed or not
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
