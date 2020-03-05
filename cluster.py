#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# External dependencies:
# textdistance:             pip3 install textdistance
# tlsh:                     pip3 install tlsh


import configparser
import pickle

import textdistance
import tlsh

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')

files = {}                  # Dictionary of of files
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
machoc_clusters = []        # List of machoc clusters
tlsh_clusters = []          # List of tlsh clusters

jaccard_index = textdistance.Jaccard.distance

def cluster_file(fileinfo):
    """
    Cluster the incoming file into existing clusters or create new clusters
    TODO: Investigate if multiple families commonly share icon (they probably do)
    """
    if fileinfo['icon_hash'] != None:                   # Cluster using a hash of the icon - fast and should be 
        icon_cluster(fileinfo)                          # suitable for both packed and non-packed samples.

    if fileinfo['obfuscation']['type'] == 'none':       # Cluster using basic features of the files if it is not packed
        if fileinfo['imphash'] != None:                 # Cluster using imphash if imphash is present (fast)
            imphash_cluster(fileinfo)
        elif fileinfo['machoc'] != None:                # Cluster using machoc hash if present (slow but accurate)
            machoc_cluster(fileinfo)
        else:                                           # Cluster using tlsh if no other suitable option
            tlsh_cluster(fileinfo)                      # TLSH should always be present (slow but fairly accurate)

def icon_cluster(fileinfo):
    if fileinfo['icon_hash'] in icon_clusters:
        icon_clusters[fileinfo['icon_hash']].append(fileinfo['sha256'])
    else:
        icon_clusters[fileinfo['icon_hash']] = [fileinfo['sha256']]

def imphash_cluster(fileinfo):
    if fileinfo['imphash'] in imphash_clusters:
        imphash_clusters[fileinfo['imphash']].append(fileinfo['sha256'])
    else:
        imphash_clusters[fileinfo['imphash']] = [fileinfo['sha256']]

def machoc_cluster(fileinfo):
    """
    Cluster file based on machoc hash.
    80 % jaccard similarity indicates a good match:
    https://github.com/ANSSI-FR/polichombr/blob/2fa9702fca21c22b68c89a98de692ccd0fa48e1d/docs/MACHOC_HASH.md#binary-comparison
    """
    threshold = 0.8
    best_score = threshold - 1
    best_cluster = None
    clusterIndex = None
    for index, cluster in enumerate(machoc_clusters):
        for otherfile in cluster:
            score = jaccard_index(fileinfo['machoc'], otherfile['machoc'])
            if score >= threshold and score > best_score:
                best_score = score
                best_cluster = cluster
                clusterIndex = index
    if best_cluster != None:            # If a suitable cluster was found
        best_cluster.append({'sha256': fileinfo['sha256'], 'machoc': fileinfo['machoc']})
        fileinfo['machoc_cluster'] = clusterIndex
    else:                               # If no cluster was found
        # If no clusters contained similar files, create new cluster
        machoc_clusters.append([{'sha256': fileinfo['sha256'], 'machoc': fileinfo['machoc']}])
        clusterIndex = len(machoc_clusters) - 1

        # Attempt to identify if other files not present in any 
        # machoc clusters should be clustered with the file
        for otherfile in files.values():
            if (otherfile['machoc'] != None
                    and otherfile['machoc_cluster'] == None
                    and fileinfo['sha256'] != otherfile['sha256']
                    and jaccard_index(fileinfo['machoc'], otherfile['machoc'])):
                    machoc_clusters[clusterIndex].append({'sha256': otherfile['sha256'], 'machoc': otherfile['machoc'])
                    otherfile['machoc_cluster'] = clusterIndex        

def tlsh_cluster(fileinfo):
    """
    Cluster file based on TrendMicro Locally Sensitive Hash
    With a threshold of 100, binary files should be fairly similar
    Treshold of 100 results in approximately 6.43% FP rate and 94.5% detect rate:
    https://doi.org/10.1109/CTC.2013.9
    """
    threshold  = 100
    best_score = threshold + 1
    best_cluster = None
    clusterIndex = None
    for index, cluster in enumerate(tlsh_clusters):
        for otherfile in cluster:
            score = tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])
            if score <= threshold and score < best_score:
                best_score = score
                best_cluster = cluster
                clusterIndex = index
    if best_cluster != None:            # If a suitable cluster was found
        best_cluster.append({'sha256': fileinfo['sha256'], 'tlsh': fileinfo['tlsh']})
        fileinfo['tlsh_cluster'] = clusterIndex
    else:                               # If no cluster was found
        # If no clusters contained similar files, create new cluster
        tlsh_clusters.append([{'sha256': fileinfo['sha256'], 'tlsh': fileinfo['tlsh']}])
        clusterIndex = len(tlsh_clusters) - 1   #  Store the index of the cluster
        fileinfo['tlsh_cluster'] = clusterIndex

        # Attempt to identify if other files not present in any 
        # tlsh clusters should be clustered with the file
        for otherfile in files.values():
            if (otherfile['tlsh_cluster'] == None 
                    and fileinfo['sha256'] != otherfile['sha256']
                    and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh']) <= threshold):
                tlsh_clusters[clusterIndex].append({'sha256': otherfile['sha256'], 'tlsh': otherfile['tlsh']})
                otherfile['tlsh_cluster'] = clusterIndex

# Read files from pickle
with open('pickles/files.pkl', 'rb') as picklefile:
    files = pickle.load(picklefile)

num_files = len(files)
i = 1

for fileinfo in files.values():     # Iterate over files to cluster them
    cluster_file(fileinfo)
    if PRINT_PROGRESS:
        print("Clustered " + str(i) + " of " + str(num_files) + " files.")

    i += 1

# Write results to pickles to allow further processing
with open('pickles/files.pkl', 'wb') as picklefile:
    pickle.dump(files, picklefile)
with open('pickles/imphash_clusters.pkl', 'wb') as picklefile:
    pickle.dump(imphash_clusters, picklefile)
with open('pickles/icon_clusters.pkl', 'wb') as picklefile:
    pickle.dump(icon_clusters, picklefile)
with open('pickles/machoc_clusters.pkl', 'wb') as picklefile:
    pickle.dump(machoc_clusters, picklefile)
with open('pickles/tlsh_clusters.pkl', 'wb') as picklefile:
    pickle.dump(tlsh_clusters, picklefile)
