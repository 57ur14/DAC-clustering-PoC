#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# External dependencies:
# tlsh:                     pip3 install tlsh


import configparser
import os
import pickle

import tlsh

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')
FAST_TLSH_CLUSTERING = config.getboolean('clustering', 'fast_tlsh_clustering')

files = {}                  # Dictionary of of files
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
resource_clusters = {}      # Dictionary of clusters where files have equal resources contained
if FAST_TLSH_CLUSTERING == True:
    tlsh_clusters = {}      # Dictionary of tlsh clusters, identified by tlsh hash of root file
else:
    tlsh_clusters = []      # List of tlsh clusters

def cluster_file(fileinfo):
    """
    Cluster the incoming file into existing clusters or create new clusters
    TODO: Investigate if multiple families commonly share icon (they probably do)
    """

    if CLUSTER_WITH_ICON == True and fileinfo['icon_hash'] != None:         # Cluster using a hash of the icon - fast and should be 
        icon_cluster(fileinfo)                          # suitable for both packed and non-packed samples (but slightly unaccurate)

    if CLUSTER_WITH_RESOURCES == True and len(fileinfo['contained_resources']) != 0:
        cluster_on_contained_resources(fileinfo)

    if fileinfo['obfuscation']['type'] == 'none':       # Cluster using basic features of the files if it is not packed
        if CLUSTER_WITH_IMPHASH == True and fileinfo['imphash'] != None:    # Cluster using imphash if imphash is present (fast)
            imphash_cluster(fileinfo)
        elif CLUSTER_WITH_TLSH == True:                 # Cluster using tlsh if no other suitable option
            tlsh_cluster(fileinfo)                      # TLSH should always be present (slow but fairly accurate)

    # TODO Add to union cluster
    # Priority if not obfuscated:
    # 1. imphash
    # 2. Resources
    # 3. TLSH
    # 4. Icon
    # Priority if obfuscated:
    # 1. Contained resources
    # 2. Parent file
    # 3. Icon

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

def cluster_on_contained_resources(fileinfo):
    for resource in fileinfo['contained_resources']:
        if resource in resource_clusters.keys():
            resource_clusters[resource].add(fileinfo['sha256'])
        else:
            resource_clusters[resource] = set([fileinfo['sha256']])

def tlsh_cluster(fileinfo):
    """
    Cluster file based on TrendMicro Locally Sensitive Hash
    """

    """
    With a threshold of 100, binary files should be fairly similar
    Treshold of 100 results in approximately 6.43% FP rate and 94.5% detect rate:
    https://doi.org/10.1109/CTC.2013.9
    """
    threshold  = 100
    best_score = threshold + 1
    best_cluster = None
    clusterIndex = None

    if FAST_TLSH_CLUSTERING == True:
        """
        Fast clustering involves only comparing to one "root node" in each clusters
        The root node is the first file added to a new cluster.
        When creating a new cluster, compare to files not present in any tlsh clusters.
        This type of clustering likely leads to lower accuracy, but increased speed.
        """
        for root_value in tlsh_clusters.keys():
            score = tlsh.diff(fileinfo['tlsh'], root_value)
            if score <= threshold and score < best_score:
                best_score = score
                best_cluster = root_value
        if best_cluster != None:
            tlsh_clusters[best_cluster].add(fileinfo['sha256'])
            fileinfo['tlsh_cluster'] = best_cluster
        else:
            tlsh_clusters[fileinfo['tlsh']] = set([fileinfo['sha256']])
            fileinfo['tlsh_cluster'] = fileinfo['tlsh']
            # TODO: Find effecient method for identifying files not in any tlsh cluster
            # Add files not in any tlsh cluster if they belong
            for otherfile in files.values():
                if (otherfile['tlsh'] != None
                        and otherfile['tlsh_cluster'] == None
                        and fileinfo['sha256'] != otherfile['sha256']
                        and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])):
                    tlsh_clusters[fileinfo['tlsh']].add(otherfile['sha256'])
    else:
        """
        Without fast clustering, each file is compared to all files in 
        all clusters as well as files not in any cluster.
        """
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
                if (otherfile['tlsh'] != None
                        and otherfile['tlsh_cluster'] == None 
                        and fileinfo['sha256'] != otherfile['sha256']
                        and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh']) <= threshold):
                    tlsh_clusters[clusterIndex].append({'sha256': otherfile['sha256'], 'tlsh': otherfile['tlsh']})
                    otherfile['tlsh_cluster'] = clusterIndex

# Read files from pickle
with open('pickles/feature_extraction/files.pkl', 'rb') as picklefile:
    files = pickle.load(picklefile)

num_files = len(files)
i = 1

for fileinfo in files.values():     # Iterate over files to cluster them
    cluster_file(fileinfo)
    if PRINT_PROGRESS:
        print("Clustered " + str(i) + " of " + str(num_files) + " files.")

    i += 1

try:
    os.mkdir('pickles/clustering')
except FileExistsError:
    pass

# Write results to pickles to allow further processing
with open('pickles/clustering/files.pkl', 'wb') as picklefile:
    pickle.dump(files, picklefile)
with open('pickles/clustering/imphash_clusters.pkl', 'wb') as picklefile:
    pickle.dump(imphash_clusters, picklefile)
with open('pickles/clustering/icon_clusters.pkl', 'wb') as picklefile:
    pickle.dump(icon_clusters, picklefile)
with open('pickles/clustering/tlsh_clusters.pkl', 'wb') as picklefile:
    pickle.dump(tlsh_clusters, picklefile)
with open('pickles/clustering/resource_clusters.pkl', 'wb') as picklefile:
    pickle.dump(resource_clusters, picklefile)
