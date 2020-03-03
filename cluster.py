#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

import tlsh

config = configparser.ConfigParser()
config.read('config.ini')
DEBUG = config.getboolean('clustering', 'debug')
DEBUG_FILECOUNT = config['clustering']['debug_filecount']
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')

files = {}                  # Dictionary of of files
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
tlsh_clusters = []          # List of tlsh clusters

def cluster_file(fileinfo):
    """
    Cluster the incoming file into existing clusters or create new clusters
    TODO: Investigate if multiple families commonly share icon (they probably do)
    """
    if fileinfo['icon_hash'] != None:                   # Cluster using a hash of the icon - fast and should be 
        icon_cluster(fileinfo)                          # suitable for both packed and non-packed samples.

    if fileinfo['obfuscation']['type'] == 'none':       # Cluster using basic features of the files if it is not packed
        if fileinfo['imphash'] != None:
            imphash_cluster(fileinfo)                   # Cluster using imphash if imphash is present (fast)
        elif fileinfo['tlsh'] != None:
            tlsh_cluster(fileinfo)                      # Cluster using tlsh if tlsh hash is present, but imphash is not (only use tlsh if no other options since it is slow)

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
        for otherfile in cluster:
            score = tlsh.diff(file['tlsh'], otherfile['tlsh'])
            if score <= threshold and score < best_score:
                best_score = score
                best_cluster = cluster
    
    if best_cluster == None:
        # If no clusters contained similar files, create new cluster
        tlsh_clusters.append([{'sha256': file['sha256'], 'tlsh': file['tlsh']}])
        clusterIndex = len(tlsh_clusters) - 1   #  Store the index of the cluster

        # Attempt to identify if other files not present in any 
        # tlsh-clusters should be clustered with the file
        for otherfile in files.values():
            if (otherfile['tlsh_cluster'] == None 
                    and file['sha256'] != otherfile['sha256']
                    and tlsh.diff(file['tlsh'], otherfile['tlsh']) <= threshold):
                tlsh_clusters[clusterIndex].append({'sha256': otherfile['sha256'], 'tlsh': otherfile['tlsh']})
                otherfile['tlsh_cluster'] = clusterIndex
    else:
        best_cluster.append({'sha256': file['sha256'], 'tlsh': file['tlsh']})

# TODO: Read from pickle and iterate over files to cluster them
# TODO: Write to new pickle