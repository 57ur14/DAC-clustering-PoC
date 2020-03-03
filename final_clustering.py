#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import pickle

config = configparser.ConfigParser()
config.read('config.ini')
DEBUG = config.getboolean('clustering', 'debug')
DEBUG_FILECOUNT = config.getint('clustering', 'debug_filecount')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')

files = {}                  # Dictionary of of files
final_clusters = []         # List of clusters created by combining other clusters
non_parsable_files = {}     # Dictionary of files that could not be parsed
incoming_files = set()      # Set of icoming files (identified by md5sum)

imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
tlsh_clusters = []          # List of tlsh clusters

def create_final_clusters():
    """
    TODO: Passer dette til online clustering?
    Må kanskje heller legge mye av dette inn i "cluster" funksjonen?
    Og hvis filen er pakket kjøre clustering på "barna" først, for å så sjekke 
    om barna er i en cluster (og i såfall legge forelderen dit)
    """
    total_pe_files = 0
    obfuscated_pe_files = 0

    for fileinfo in files.values():
        total_pe_files += 1
        if fileinfo['final_cluster'] == None:
            # Create new cluster if it is not in a final cluster
            cluster_set = set([fileinfo['sha256']])
            final_clusters.append(cluster_set)
            clusterIndex = len(final_clusters) - 1
            fileinfo['final_cluster'] = clusterIndex
        else:
            # Or use current cluster if it is in a cluster
            cluster_set = final_clusters[fileinfo['final_cluster']]

        if CLUSTER_WITH_ICON == True and fileinfo['icon_hash'] != None:
            for sha256sum in icon_clusters[fileinfo['icon_hash']]:
                if files[sha256sum]['final_cluster'] == None:
                    cluster_set.add(sha256sum)
                    files[sha256sum]['final_cluster'] = fileinfo['final_cluster']
        if fileinfo['obfuscation']['type'] == 'none':
            if fileinfo['imphash'] != None:
                for sha256sum in imphash_clusters[fileinfo['imphash']]:
                    if files[sha256sum]['final_cluster'] == None:
                        cluster_set.add(sha256sum)
                        files[sha256sum]['final_cluster'] = fileinfo['final_cluster']
            if fileinfo['tlsh_cluster'] != None:
                for otherfile in tlsh_clusters[fileinfo['tlsh_cluster']]:
                    if files[otherfile['sha256']]['final_cluster'] == None:
                        cluster_set.add(otherfile['sha256'])
                        files[otherfile['sha256']]['final_cluster'] = fileinfo['final_cluster']

            # Add parent files to the cluster of the current file if the parent
            # is not already present in a cluster or alone in a cluster
            for parentfile in fileinfo['unpacks_from']:
                # If the parent file is alone in a cluster
                if (files[parentfile]['final_cluster'] != None 
                        and len(final_clusters[files[parentfile]['final_cluster']]) == 1):
                    # Remove from the cluster (but don't remove the cluster from 
                    # the list of clusters) before adding to the cluster of the child
                    final_clusters[files[parentfile]['final_cluster']].remove(parentfile)
                    files[parentfile]['final_cluster'] = None

                if files[parentfile]['final_cluster'] == None:
                    # Add to cluster of the child if the parent is not in a cluster
                    cluster_set.add(parentfile)
                    files[parentfile]['final_cluster'] = fileinfo['final_cluster']
        else:
            obfuscated_pe_files += 1
    print("Number obfuscated pe files: " + str(obfuscated_pe_files))
    print("Total pe files: " + str(total_pe_files))

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

    with open('results/final_clusters.txt', 'w') as outfile:
        for cluster in final_clusters:
            if len(cluster) == 1:
                continue                # Skip clusters with only 1 file
                # TODO: Er mange filer som kun clusteres sammen med én utpakket fil
                # Det vil egentlig være lite hensiktsmessig å ta med dette som egne clustere.
                # Disse bør også fjernes (og så kan man heller skrive ut dette under nonclustered)
            for file_checksum in cluster:
                if files[file_checksum]['md5'] in incoming_files:
                    outfile.write("+")  # Incoming file clustered
                else:
                    outfile.write("-")  # Unpacked file, can be ignored
                outfile.write(file_checksum + ' ' + files[file_checksum]['family'] + ' ' + files[file_checksum]['md5'] + "\n")
            outfile.write("\n")

    with open('results/nonclustered.txt', 'w') as outfile:
        for fileinfo in files.values():
            # Output list of files that are alone in a cluster or not in any cluster
            if fileinfo['final_cluster'] == None or len(final_clusters[fileinfo['final_cluster']]) == 1:
                if fileinfo['md5'] in incoming_files:
                    outfile.write("-")  # Incoming file not clustered (failure)
                else:
                    outfile.write("+")  # New file (unpacked from other, can be ignored)
                outfile.write(fileinfo['sha256'] + ' ' + fileinfo['family'] + ' ' + fileinfo['md5'] + "\n" )

# Read from pickles
with open('pickles/files.pkl', 'rb') as picklefile:
    files = pickle.load(picklefile)
with open('pickles/imphash_clusters.pkl', 'rb') as picklefile:
    imphash_clusters = pickle.load(picklefile)
with open('pickles/icon_clusters.pkl', 'rb') as picklefile:
    icon_clusters = pickle.load(picklefile)
with open('pickles/tlsh_clusters.pkl', 'rb') as picklefile:
    tlsh_clusters = pickle.load(picklefile)
with open('pickles/incoming_files.pkl', 'rb') as picklefile:
    incoming_files = pickle.load(picklefile)
with open('pickles/non_parsable_files.pkl', 'rb') as picklefile:
    non_parsable_files = pickle.load(picklefile)

# Cluster by using union on other clusters
create_final_clusters()

# Write results to files
write_result_to_files()