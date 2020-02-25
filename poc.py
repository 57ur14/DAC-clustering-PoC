#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tlsh
import hashlib
import pefile
import peicoex
import pyhash
import unpacking
import packer_detection
import filetype

base_directory = '/home/sturla/IJCNN_10000files/'
files = {}                  # List of files that are to be clustered
parent_files = {}
unknown_files = {}          # List of packed files (should not be compared against for most features)
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
tlsh_clusters = []          # List of tlsh clusters
xxhasher = pyhash.xx_64()

def main():
    load_historic_data()
    """
    print("\nIcon clusters:")
    for iconhash in icon_clusters.keys():
        print(iconhash)
        for file in icon_clusters[iconhash]:
            print(file)
        print("\n")

    print("Imphash clusters:")
    for imphash in imphash_clusters.keys():
        print(imphash)
        for file in imphash_clusters[imphash]:
            print(file)
        print("\n")
    
    print("tlsh clusters:")
    for cluster in tlsh_clusters:
        #print(cluster['root'])
        for file in cluster:
            print(file)
        #for file in cluster['files']:
            #print(file['path'])
        print("\n")
    """
    #for key in parent_files.keys():
    #    print(parent_files[key])
    #    print("\n")

def analyse_file(fullfilepath, family=None, unpacks_from=None):
    """
    Analyse a pe-file at the given filepath.
    Can also specify the family the pe belongs to (if known) and the 
    sha256sum of the file that that unpacked the incoming file.

    If "family" is None, it means that the family is unknown.
    """

    with open(fullfilepath, 'rb') as filehandle:
        rawfile = filehandle.read()

        fileinfo = {
            'fullpath': fullfilepath, 
            'md5': hashlib.md5(rawfile).hexdigest(),
            'sha256': hashlib.sha256(rawfile).hexdigest(),
            'family': family, 
            'unpacks_from': unpacks_from, 
            'suspicious': False, 
            'contained_pe_files': [],
            'contained_resources': []
        }

        if fileinfo['sha256'] == unpacks_from:
            return None     # Return none if the file is identical to the parent

        try:
            pe = pefile.PE(data=rawfile)
        except Exception as err:
            return None             # If the file cannot be parsed by pefile, skip it?
            # TODO: Should probably do something if unpacks_from == None....
        
        pe.parse_data_directories()
        
        # Extract all features regardless of obfuscation
        fileinfo['icon_hash'] = get_icon_hash(pe)
        fileinfo['pefile_warnings'] = pe.get_warnings()
        fileinfo['imphash'] = pe.get_imphash()
        fileinfo['tlsh'] = tlsh.hash(rawfile)
        fileinfo['obfuscation'] = packer_detection.detect_obfuscation(fullfilepath, pe, fileinfo['pefile_warnings'])
        if len(fileinfo['pefile_warnings']) != 0:       # Simple method of identifying if file seems suspicious
            # TODO: Investigate peutils -> is_suspicious(pe) (function)
            fileinfo['suspicious'] = True

        if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            # Packed files should be removed from list of other files (to avoid creating clusters of files created with the same packer)
            unpacked = unpacking.unpack_file(fullfilepath, fileinfo['obfuscation'], pe)
            
            if len(unpacked):
                fileinfo['contained_pe_files'] = []
                for unpacked_file in unpacked:
                    if filetype.guess_mime(unpacked_file) == 'application/x-msdownload': # Check if the file is an "exe" (pe file)
                        analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=fileinfo['sha256'])
                        if analysis_result != None:
                            fileinfo['contained_pe_files'].append(analysis_result)
                            continue
                    # If the file is not a pe file or the pe file is corrupt, 
                    # simply add a hash of the unpacked file to "contained resources"
                    fileinfo['contained_resources'].append(unpacked_file.split('/')[-1])
        
        # TODO: Separate clustering into its own function?
        # Analysis can be performed in parallell by "slaves" provided that a 
        # single "master" collects and stores the generated data.

            else:                                       # unpacked == [] (Could not unpack any files)
                if fileinfo['icon_hash'] != None:
                    icon_cluster(fileinfo)
                elif len(fileinfo['contained_resources']):
                    pass # TODO: Cluster based on the contained resources?
                else:                                   # Add to list of unknown files
                    unknown_files[fileinfo['sha256']] = fileinfo
        else:                                           # If file does not seem to be packed / protected
            if fileinfo['imphash'] != None:
                imphash_cluster(fileinfo)               # Cluster using imphash if imphash is present
            elif fileinfo['tlsh'] != None:
                tlsh_cluster(fileinfo)
            else:                                       # Add to list of unknown files
                unknown_files[fileinfo['sha256']] = fileinfo

        if fileinfo['obfuscation']['type'] == 'none':
            files[fileinfo['sha256']] = fileinfo
        else:
            unknown_files[fileinfo['sha256']] = fileinfo

        return fileinfo['sha256']                       # Return the sha256sum of the pe file
    return None                                         # Return None if the file could not be opened

def icon_cluster(file):
    if file['icon_hash'] in icon_clusters:
        icon_clusters[file['icon_hash']].append(file['sha256'])
    else:
        icon_clusters[file['icon_hash']] = [file['sha256']]

def imphash_cluster(file):
    if file['imphash'] in imphash_clusters:
        imphash_clusters[file['imphash']].append(file['sha256'])
    else:
        imphash_clusters[file['imphash']] = [file['sha256']]

"""
#Comparing with root nodes only
def tlsh_cluster(file):
    threshold  = 100
    best_score = threshold + 1
    best_cluster = None
    for cluster in tlsh_clusters:
        score = tlsh.diff(file['tlsh'], cluster['root'])
        if score <= threshold and score < best_score:
            best_score = score
            best_cluster = cluster
    if best_cluster == None:
        tlsh_clusters.append({'root': file['tlsh'], 'files': [file['fullpath']]})
    else:
        best_cluster['files'].append(file['fullpath'])
"""

def tlsh_cluster(file):
    """
    Cluster file based on TrendMicro Locally Sensitive Hash
    With a threshold of 100, the files should be fairly similar.
    TODO: Kilde på 100 som threshold
    """
    threshold  = 100
    best_score = threshold + 1
    best_cluster = None
    for cluster in tlsh_clusters:
        for cfile in cluster:
            score = tlsh.diff(file['tlsh'], cfile['tlsh'])
            if score <= threshold and score < best_score:
                best_score = score
                best_cluster = cluster
    if best_cluster == None:
        tlsh_clusters.append([{'sha256': file['sha256'], 'tlsh': file['tlsh']}])
    else:
        best_cluster.append({'sha256': file['sha256'], 'tlsh': file['tlsh']})

def get_icon_hash(pefile_pe):
    """
    Retrieve a hash of the icon a Windows system would prefer to use.
    Returns None if no RT_GROUP_ICON was found or the icon could not be extracted properly.
    https://docs.microsoft.com/en-us/windows/win32/menurc/about-icons#icon-display
    TODO: Beskriv hvorfor xxhash64 brukes: https://aras-p.info/blog/2016/08/02/Hash-Functions-all-the-way-down/
    """
    icon_hash = None
    extract = peicoex.ExtractIcon(pefile_pe=pefile_pe)
    group_icons = extract.get_group_icons()
    if group_icons != None:
        best_icon = 0
        for group in group_icons:
            if len(group) == 0:
                print("No entries in group!")
                continue
            best_icon = extract.best_icon(group)
            raw = extract.export_raw(group, best_icon)
            icon_hash = xxhasher(raw)
            break                   # System would only use first icon group (although others might be interesting..)
    return icon_hash

def load_historic_data():
    """
    Load historic / training data. 
    Retrieves a list of the files from a specified txt file.
    Sends all files to the "analyse_file" function that extracts features and clusters files.
    """
    
    with open('/home/sturla/poc/train.txt', 'r') as trainfilesfile:
        train = trainfilesfile.read().splitlines()
        
        num_files = len(train)

        i = 0
        for trainFile in train:

            path = base_directory + trainFile
            fam = trainFile.split('/')[0]

            analyse_file(path, family=fam)
            
            i += 1
            #print("Analysed " + str(i) + " of " + str(num_files) + " files.")
            #if i == 1000: # TODO: Remove (test with 1000 files)
            #    break


main()                  # Begin exectuion after parsing the whole file