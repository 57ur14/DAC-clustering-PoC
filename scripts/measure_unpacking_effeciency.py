#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import filetype
import pefile
import hashlib
import os
import tempfile

import unpacking

tempdirObject = tempfile.TemporaryDirectory()
tmp = tempdirObject.name

total_unpacked_pe = 0
total_unpacked_resources = 0
incoming_that_unpack_to_nonpacked_pe = 0
incoming_that_unpack_to_resource = 0
incoming_unpacked = 0

def analyse_file(fullfilepath, family=None, incoming=False, unpacks_from=set(), unpack_chain=None, unpack_method='all'):
    global total_unpacked_pe
    global total_unpacked_resources
    global incoming_that_unpack_to_nonpacked_pe
    global incoming_unpacked
    global incoming_that_unpack_to_resource

    with open(fullfilepath, 'rb') as filehandle:
        rawfile = filehandle.read()

        fileinfo = {
            'fullpath': fullfilepath,
            'md5': hashlib.md5(rawfile).hexdigest(),
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family,
            'incoming': incoming,
            'suspicious': False,
            'obfuscation': None,
            'unpacks_from': unpacks_from,
            'contained_pe_files': set(),
            'unpacks_to_nonpacked_pe': False,
            'unpacks_to_resource': False,
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
            # If file cannot be parsed with pefile, 
            # Return None
            return None

        pe.parse_data_directories()
        fileinfo['pefile_warnings'] = pe.get_warnings()
        if len(fileinfo['pefile_warnings']) != 0:
            # Simple method of identifying if file seems suspicious
            fileinfo['suspicious'] = True

        fileinfo['obfuscation'] = unpacking.detect_obfuscation_by_diec(fullfilepath)
        if True:
            # Attempt unpacking all files
            #if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            # Attempt to unpack the packed file
            unpacked = []
            if unpack_method == 'all':
                unpacked = unpacking.unpack_file(fullfilepath, fileinfo, pe)
            elif (unpack_method == 'clamav'
                    and (('packer' in fileinfo['obfuscation'] 
                    and fileinfo['obfuscation']['packer'] in unpacking.clam_supported_packers) 
                    or ('protector' in fileinfo['obfuscation'] 
                    and fileinfo['obfuscation']['protector'] in unpacking.clam_supported_packers))):
                unpacked = unpacking.clam_unpack(fullfilepath, tmp)
            elif (unpack_method == 'unipacker'
                    and (('packer' in fileinfo['obfuscation'] 
                    and fileinfo['obfuscation']['packer'] in unpacking.clam_supported_packers) 
                    or ('protector' in fileinfo['obfuscation'] 
                    and fileinfo['obfuscation']['protector'] in unpacking.clam_supported_packers))):
                unpacked = unpacking.unipack(fullfilepath, tmp)
            elif (unpack_method == 'upx'
                    and 'packer' in fileinfo['obfuscation'] 
                    and 'upx' in fileinfo['obfuscation']['packer']):
                unpacked = unpacking.unpack_upx(fullfilepath, tmp)
            elif unpack_method == 'none':
                pass # Don't do anything. Leave unpacked empty

            if incoming and unpacked:
                incoming_unpacked += 1

            for unpacked_file in unpacked:              # For all unpacked files
                if filetype.guess_mime(unpacked_file) == 'application/x-msdownload':
                    # Check if the file is an "exe" (pe file) and analyse it if so
                    if (unpack_chain is not None 
                            and len(unpack_chain) >= 20):
                        # Skip unpacking if this file has been recursively unpacking 
                        # more than a specified number of times.
                        continue
                    analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=set([fileinfo['sha256']]), unpack_chain=unpack_chain, unpack_method=unpack_method)
                    if analysis_result is not None:
                        total_unpacked_pe += 1
                        # If file could be parsed by pefile
                        if (analysis_result['obfuscation']['type'] == 'none'
                                or analysis_result['unpacks_to_nonpacked_pe']):
                            # If contained file is not packed or unpacks to a nonpacked file
                            # Mark this file as "unpacks to nonpacked pe"
                            fileinfo['unpacks_to_nonpacked_pe'] = True
                        if analysis_result['unpacks_to_resource']:
                            fileinfo['unpacks_to_resource'] = True
                        fileinfo['contained_pe_files'].add(analysis_result['sha256'])
                        fileinfo['contained_pe_fileinfo'][analysis_result['sha256']] = analysis_result
                else:
                    # If the file is not a pe file or the pe file is corrupt, 
                    # simply add a hash of the unpacked file to "contained resources"
                    fileinfo['contained_resources'].add(os.path.basename(unpacked_file))
                    fileinfo['unpacks_to_resource'] = True
                    total_unpacked_resources += 1
        if incoming and fileinfo['unpacks_to_nonpacked_pe']:
            incoming_that_unpack_to_nonpacked_pe += 1
        if incoming and fileinfo['unpacks_to_resource']:
            incoming_that_unpack_to_resource += 1
        return fileinfo
    return None

with open('ijcnn_filepaths_randomised.txt') as infile:
    lines = infile.read().splitlines()
    for line in lines:
        filepath, family = line.split(' ')
        print(filepath)
        method = 'all'
        analyse_file(filepath, family=family, incoming=True, unpack_method=method)

    print("Total unpacked pe files: " + str(total_unpacked_pe))
    print("Total unpacked resources: " + str(total_unpacked_resources))
    print("Incoming files that could be unpacked to anything: " + str(incoming_unpacked))
    print("Incoming files that unpack to a non-packed PE: " + str(incoming_that_unpack_to_nonpacked_pe))
    print("Incoming files that unpack to at least one non-PE file (resource): " + str(incoming_that_unpack_to_resource))