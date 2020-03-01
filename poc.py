#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tlsh
import hashlib
import pefile
import peicoex
import pyhash
import unpacking
import packer_detection
import filetype

base_directory = '/home/sturla/IJCNN_10000files/'
files = {}                  # Dictionary of of files
non_parsable_files = {}     # Dictionary of files that could not be parsed
non_clustered_files = []    # List of files that have not been added to any clusters
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
tlsh_clusters = []          # List of tlsh clusters
tlsh_nonclustered = []      # List of files (sha256sums) present in any tlsh cluster
final_clusters = []         # List of clusters created by combining other clusters
xxhasher = pyhash.xx_64()

DEBUG = True
DEBUG_FILECOUNT = 1000
PRINT_PROGRESS = True
CLUSTER_WITH_ICON = False

def main():
    load_historic_data()

    create_final_clusters()

    write_result_to_files()

def analyse_file(fullfilepath, family=None, unpacks_from=[]):
    """
    Analyse a pe-file at the given filepath, add to list of files and return sha256sum
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
            'suspicious': False,
            'unpacks_from': unpacks_from,
            'contained_pe_files': [],
            'contained_resources': [],
            'imphash': None,
            'icon_hash': None,
            'tlsh': tlsh.hash(rawfile),
            'tlsh_cluster': None,
            'final_cluster': None
        }

        # Use previously gathered information if a file with equal sha256sum already has been analysed
        if (fileinfo['sha256'] in files.keys()) and (fileinfo['sha256'] not in files[fileinfo['sha256']]['unpacks_from']):
            files[fileinfo['sha256']]['unpacks_from'].append(fileinfo['sha256'])
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
        fileinfo['obfuscation'] = packer_detection.detect_obfuscation(fullfilepath, pe, fileinfo['pefile_warnings'])
        if len(fileinfo['pefile_warnings']) != 0:       # Simple method of identifying if file seems suspicious
            fileinfo['suspicious'] = True               # TODO: Investigate peutils -> is_suspicious(pe) (function in peutils.py)

        if fileinfo['obfuscation']['type'] != 'none':   # If file seems to be packed
            # Packed files should be removed from list of other files (to avoid creating clusters of files created with the same packer)
            unpacked = unpacking.unpack_file(fullfilepath, fileinfo, pe)
            
            for unpacked_file in unpacked:              # For all unpacked files
                if filetype.guess_mime(unpacked_file) == 'application/x-msdownload': # Check if the file is an "exe" (pe file)
                    analysis_result = analyse_file(unpacked_file, family=family, unpacks_from=[fileinfo['sha256']])
                    if analysis_result != None:
                        fileinfo['contained_pe_files'].append(analysis_result)
                        continue
                # If the file is not a pe file or the pe file is corrupt, 
                # simply add a hash of the unpacked file to "contained resources"
                fileinfo['contained_resources'].append(os.path.basename(unpacked_file))
        
        files[fileinfo['sha256']] = fileinfo            # Add to list of files
        tlsh_nonclustered.append(fileinfo['sha256'])    # Add to list of files not clustered by tlsh

        return fileinfo['sha256']                       # Return the sha256sum of the pe file
    return None                                         # Return None if the file could not be opened

def cluster_file(fileinfo):
    # TODO: Investigate if multiple families commonly share icon
    if fileinfo['icon_hash'] != None:                   # Cluster using a hash of the icon - fast and should be 
        icon_cluster(fileinfo)                          # suitable for both packed and non-packed samples.

    if fileinfo['obfuscation']['type'] == 'none':       # Cluster using basic features of the files if it is not packed
        if fileinfo['imphash'] != None:
            imphash_cluster(fileinfo)                   # Cluster using imphash if imphash is present (fast)
        elif fileinfo['tlsh'] != None:
            tlsh_cluster(fileinfo)                      # Cluster using tlsh if tlsh hash is present, but imphash is not (only use tlsh if no other options since it is slow)
    else:                                               # Cluster using features copied to packed header or features of unpacked files if the file is packed
        #elif len(fileinfo['contained_pe_files']):
        #    pass                                        # TODO: Cluster based on unpacked pe files?
        #elif len(fileinfo['contained_resources']):
        #    pass                                        # TODO: Cluster based on contained resources?
        #else:               # If no suitable features are avialable, add to list of files that have not been clustered
        #    non_clustered_files.append(fileinfo['sha256'])
        non_clustered_files.append(fileinfo['sha256'])

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
    
    if best_cluster == None:                        # If no clusters contained similar files
        tlsh_clusters.append([{'sha256': file['sha256'], 'tlsh': file['tlsh']}]) # Create new cluster
        clusterIndex = len(tlsh_clusters) - 1       # Store the index of the cluster

        # Attempt to identify if other files not present in any 
        # tlsh-clusters should be clustered with the file
        for otherfile in files.values():
            if (otherfile['tlsh_cluster'] == None 
                    and file['sha256'] != otherfile['sha256']
                    and tlsh.diff(file['tlsh'], otherfile['tlsh']) <= threshold):
                tlsh_clusters[clusterIndex].append({'sha256': otherfile['sha256'], 'tlsh': otherfile['tlsh']})
                otherfile['tlsh_cluster'] = clusterIndex
    else:
        tlsh_nonclustered.remove(file['sha256'])    # Remove from list of files not clustered with tlsh
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
            
            if PRINT_PROGRESS:
                print("Analysed " + str(i) + " of " + str(num_files) + " files.")
            if DEBUG == True and i == DEBUG_FILECOUNT:
                break       # Only process a certain number of files if debugging
        
        for fileinfo in files.values():
            cluster_file(fileinfo)

def create_final_clusters():
    for fileinfo in files.values():
        if fileinfo['final_cluster'] == None:
            cluster_set = set()
            cluster_set.add(fileinfo['sha256'])

            if fileinfo['icon_hash'] != None and CLUSTER_WITH_ICON == True:
                for sha256sum in icon_clusters[fileinfo['icon_hash']]:
                    cluster_set.add(sha256sum)
            if fileinfo['obfuscation']['type'] == 'none':
                if fileinfo['imphash'] != None:
                    for sha256sum in imphash_clusters[fileinfo['imphash']]:
                        cluster_set.add(sha256sum)
                if fileinfo['tlsh_cluster'] != None:
                    for otherfile in tlsh_clusters[fileinfo['tlsh_cluster']]:
                        cluster_set.add(otherfile['sha256'])
            
            final_clusters.append(cluster_set)
            clusterIndex = len(final_clusters) - 1
            fileinfo['final_cluster'] = clusterIndex
        else:
            # TODO: Extend the current cluster by this files other features?
            # Example: It was added to a cluster due to similar TLSH, but is in 
            # a different imphash cluster with other files not present in the TLSH cluster
            # that could be added to the current cluster.
            pass

def write_result_to_files():
    """
    Write results to files in the results/ directory
    """
    try:
        os.mkdir('results')
    except FileExistsError:
        pass

    print("Writing output to the directory results/")

    with open('results/features.txt', 'w') as outfile:
        for fileinfo in files.values():
            outfile.write(str(fileinfo) + "\n\n")
    
    with open('results/iconhash_cluster.txt', 'w') as outfile:
        for iconhash in icon_clusters.keys():
            outfile.write("\n" + str(iconhash) + "\n")
            for file in icon_clusters[iconhash]:
                outfile.write(file + "\n")

    with open('results/imphash_cluster.txt', 'w') as outfile:
        for imphash in imphash_clusters.keys():
            outfile.write("\n" + imphash + "\n")
            for file in imphash_clusters[imphash]:
                outfile.write(file + "\n")
    
    with open('results/tlsh_cluster.txt' ,'w') as outfile:
        for cluster in tlsh_clusters:
            outfile.write("\n")
            for fileinfo in cluster:
                outfile.write(str(fileinfo) + "\n")
    
    with open('results/nonparsable.txt', 'w') as outfile:
        for fileinfo in non_parsable_files.values():
            outfile.write(str(fileinfo) + "\n\n")
    
    with open('results/nonclustered.txt', 'w') as outfile:
        for file_checksum in non_clustered_files:
            outfile.write(file_checksum + "\n")

    with open('results/final_clusters.txt', 'w') as outfile:
        for cluster in final_clusters:
            for file_checksum in cluster:
                outfile.write(file_checksum + " " + files[file_checksum]['family'] + "\n")
            outfile.write("\n")


main()                  # Begin exectuion after parsing the whole file
print("Done")