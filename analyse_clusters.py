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
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')

files = {}                  # Dictionary of of files
non_parsable_files = {}     # Dictionary of files that could not be parsed
nonclustered = set()        # Set of files not belonging to a cluster
stats = {
    'number_of_incoming_pe': 0,
    'unpacked_pe_files': 0,
    'successfully_unpacked_incoming': 0,
    'total_pe_files': 0,
    'total_obfuscated_pe_files': 0,
    'obfuscated_unpacked_pe_files': 0,
    'obfuscated_incoming_pe_files': 0,
    'number_of_good_clusters': 0,
    'total_clustered_files': 0,
    'mean_cluster_size': 0,
    'successfully_clustered_incoming': 0,
    'not_clustered_incoming': 0,
    'share_successful': 0
}                           # Dictionary to store statistics of the clustering

imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
tlsh_clusters = {}      # Dictionary of tlsh clusters, identified by tlsh hash of root file
union_clusters = []

def create_final_clusters():
    """
    TODO: Passer dette til online clustering?
    Må kanskje heller legge mye av dette inn i "cluster" funksjonen?
    Og hvis filen er pakket kjøre clustering på "barna" først, for å så sjekke 
    om barna er i en cluster (og i såfall legge forelderen dit)
    """

    # Filter out certain files that are in very small clusters
    # TODO: Filter clutsers that only contain 1 or 0 "incoming_files"?
    for cluster in union_clusters:
        if len(cluster) == 1:                   # Move files to "nonclustered"
            sha256 = cluster.pop()              # if they are alone in a cluster
            nonclustered.add(sha256)
            files[sha256]['union_cluster'] = None
        elif len(cluster) == 2:
            # Move files to "nonclustered" if one file was unpacked from the 
            # other file, or less than 2 files were originally incoming files
            f1 = cluster.pop()
            f2 = cluster.pop()
            if (files[f1]['unpacks_from'] == f2 
                    or files[f2]['unpacks_from'] == f1
                    or files[f1]['incoming'] == False
                    or files[f2]['incoming'] == False):
                nonclustered.add(f1)
                nonclustered.add(f2)
                files[f1]['union_cluster'] = None
                files[f2]['union_cluster'] = None
            else:
                cluster.add(f1)
                cluster.add(f2)
        else:
            # Check if the cluster contains at least 2 files that are in "incoming_files"
            number_of_incoming_files_in_cluster = 0
            for sha256 in cluster:
                if files[sha256]['incoming'] == True:
                    number_of_incoming_files_in_cluster += 1
            if number_of_incoming_files_in_cluster < 2:
                # Remove cluster if less than 2 files were incoming
                for sha256 in cluster:
                    nonclustered.add(sha256)
                    files[sha256]['union_cluster'] = None
                cluster.clear()
            else:
                stats['total_clustered_files'] += len(cluster)
                stats['number_of_good_clusters'] += 1
    
    for fileinfo in files.values():
        if fileinfo['incoming'] == True:
            # Gather info in all files that were incoming 
            # (and not unpacked from another PE)

            # Count as incoming pe
            stats['number_of_incoming_pe'] += 1

            if fileinfo['obfuscation']['type'] != 'none':
                # Count as an obfuscated incoming file if packed
                stats['obfuscated_incoming_pe_files'] += 1

                if (fileinfo['unpacks_to_nonpacked_pe'] == True
                        or fileinfo['contained_resources']):
                    # If incoming, packed file was unpacked to nonpacked
                    # pe or a resource, count as successfully unpacked
                    stats['successfully_unpacked_incoming'] += 1
            if fileinfo['union_cluster'] != None:
                # Successfully clustered if in a cluster
                stats['successfully_clustered_incoming'] += 1
            else:
                # Unsuccessful if not in a cluster
                stats['not_clustered_incoming'] += 1
        elif fileinfo['obfuscation']['type'] != 'none':
            # If not incomung but obfuscated, count as obfuscated unpacked
            stats['obfuscated_unpacked_pe_files'] += 1

    # Identify cluster "purity"
    mean_purity = 0
    num_real_clusters = 0
    num_pure_clusters = 0

    for cluster in union_clusters:
        if len(cluster) == 0:
            continue

        num_real_clusters += 1
        families_in_cluster = {}
        for sha256 in cluster:
            family = files[sha256]['family']
            if family not in families_in_cluster:
                families_in_cluster[family] = 1
            else:
                families_in_cluster[family] += 1
        # Retrieve the most common family (might be even, but should not matter)
        most_common_family = max(families_in_cluster, key=families_in_cluster.get)
        num_files_in_cluster = sum(families_in_cluster.values())
        num_files_in_most_common = families_in_cluster[most_common_family]
        #num_in_other_families = num_files_in_cluster - num_files_in_most_common
        cluster_purity = num_files_in_most_common / num_files_in_cluster
        mean_purity += cluster_purity
        if num_files_in_most_common == num_files_in_cluster:
            num_pure_clusters += 1

    stats['total_pe_files'] = len(files)
    stats['unpacked_pe_files'] = stats['total_pe_files'] - stats['number_of_incoming_pe']
    stats['total_obfuscated_pe_files'] = stats['obfuscated_unpacked_pe_files'] + stats['obfuscated_incoming_pe_files']
    if stats['number_of_good_clusters'] != 0:
        stats['mean_cluster_size'] = stats['total_clustered_files'] / stats['number_of_good_clusters']
    if stats['number_of_incoming_pe'] != 0:
        stats['share_successful'] = stats['successfully_clustered_incoming'] / stats['number_of_incoming_pe']
    if num_real_clusters != 0:
        stats['mean_purity'] = mean_purity / num_real_clusters
    stats['total_pure_clusters'] = num_pure_clusters
    stats['total_clusters'] = num_real_clusters

    for key, value in stats.items():
        print(str(key) + ": " + str(value))

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
        for root_hash, cluster_files in tlsh_clusters.items():
            outfile.write("\n" + root_hash + ":\n")
            for sha256 in cluster_files:
                outfile.write(sha256 + "\n")
    
    # TODO: What happens to files that cannot be parsed?
    #with open('results/nonparsable.txt', 'w') as outfile:
    #    for fileinfo in non_parsable_files.values():
    #        outfile.write(str(fileinfo) + "\n\n")

    with open('results/union_clusters.txt', 'w') as outfile:
        for cluster in union_clusters:
            if len(cluster) == 0:
                continue                # Skip clusters with no files
            for file_checksum in cluster:
                if files[file_checksum]['incoming'] == True:
                    outfile.write("+")  # Incoming file clustered
                else:
                    outfile.write("-")  # Unpacked file, can be ignored
                outfile.write(file_checksum + ' ' + files[file_checksum]['family'] + ' ' + files[file_checksum]['md5'] + "\n")
            outfile.write("\n")

    with open('results/nonclustered.txt', 'w') as outfile:
        for fileinfo in files.values():
            # Output list of files that are alone in a cluster or not in any cluster
            if fileinfo['union_cluster'] == None:
                if fileinfo['incoming'] == True:
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
with open('pickles/resource_clusters.pkl', 'rb') as picklefile:
    resource_clusters = pickle.load(picklefile)
with open('pickles/tlsh_clusters.pkl', 'rb') as picklefile:
    tlsh_clusters = pickle.load(picklefile)
with open('pickles/union_clusters.pkl', 'rb') as picklefile:
    union_clusters = pickle.load(picklefile)
# TODO: What happens with non-parsable files?
#with open('pickles/feature_extraction/non_parsable_files.pkl', 'rb') as picklefile:
#    non_parsable_files = pickle.load(picklefile)


# Cluster by using union on other clusters
create_final_clusters()

# Write results to files
write_result_to_files()