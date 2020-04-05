# -*- coding: utf-8 -*-

# External dependencies:
# tlsh

import configparser
from collections import Counter
import os
import pickle

import tlsh

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_CONTAINED_PE = config.getboolean('clustering', 'cluster_with_contained_pe')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')
TLSH_THRESHOLD = config.getint('clustering', 'tlsh_threshold')
TLSH_FAST_CLUSTERING = config.getboolean('clustering', 'tlsh_fast_clustering')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')

def cluster_files(files, clusters):
    """
    Create clusters based on file features
    """

    for sha256 in files.keys():
        # Iterate over files and attempt to cluster
        # the file with fast clustering methods/features
        fileinfo = files[sha256]
        fast_cluster_file(fileinfo, clusters)
    
    for sha256 in files.keys():
        # Iterate over files again to cluster the remaining files
        fileinfo = files[sha256]
        if not fileinfo['fast_clustered']:
            # If the file has not been clustered with fast properties
            if CLUSTER_WITH_CONTAINED_PE and fileinfo['contained_pe_files']:
                # Attempt to cluster the file on contained PE files
                fast_cluster_on_contained_files(fileinfo, files, clusters)
            if not fileinfo['fast_clustered']:
                # If still not fast clustered, cluster slowly
                if fileinfo['incoming']:
                    while True:
                        print("Slow clustering an incoming file!")
                slow_cluster_file(fileinfo, files, clusters)

def fast_cluster_file(fileinfo, clusters):
    """
    TODO: Dokumenter
    """
    if CLUSTER_WITH_RESOURCES and fileinfo['contained_resources']:
        # Cluster with resources if file contained resources
        cluster_on_contained_resources(fileinfo, clusters['resource_clusters'])
        fileinfo['fast_clustered'] = True

    if CLUSTER_WITH_ICON and fileinfo['icon_hash']:
        # Cluster using a hash of the icon
        cluster_using_equal_values('icon_hash', fileinfo, clusters['icon_clusters'])
        fileinfo['fast_clustered'] = True

    if fileinfo['obfuscation'] is None or CLUSTER_PACKED_FILES:
        # If file is not obfuscated or the configuration
        # specifies that obfuscated files should be packed

        if CLUSTER_WITH_IMPHASH and fileinfo['imphash']:
            # Cluster with imphash
            cluster_using_equal_values('imphash', fileinfo, clusters['imphash_clusters'])
            fileinfo['fast_clustered'] = True

def fast_cluster_on_contained_files(fileinfo, files, clusters):
    """
    TODO: Dokumenter
    """
    for contained in fileinfo['contained_pe_files']:
        otherfile = files[contained]
        # Iterate over contained files
        if not otherfile['fast_clustered']:
            # Before clustering the contained file, recursively
            # fast cluster the files contained in this the current file
            fast_cluster_on_contained_files(otherfile, files, clusters)
        if otherfile['fast_clustered']:
            # If the contained file has been fast clustered 
            # (based on the files contained inside of it),
            # fast cluster this file based on the contained file
            fast_cluster_on_contained_file(fileinfo, otherfile, clusters)
            return True
    return False

def fast_cluster_on_contained_file(original, contained, clusters):
    """
    TODO: Dokumenter
    """
    # Create a new "fake" fileinfo.
    # It has the features of the contained file, but
    # the sha256 checksum of the original file
    # so that this file's checksum is added to the clusters
    # the contained file would be added to
    fake_info = contained.copy()
    fake_info['sha256'] = original['sha256']
    fast_cluster_file(fake_info, clusters)
    original['fast_clustered'] = True

def slow_cluster_file(fileinfo, files, clusters):
    # Cluster with slow methods only if not yet clustered
    if CLUSTER_WITH_TLSH and fileinfo['tlsh']:
        cluster_using_tlsh(fileinfo, files, clusters['tlsh_clusters'])
        fileinfo['slow_clustered'] = True

def cluster_on_contained_resources(fileinfo, resource_clusters):
    """
    TODO: Dokumenter
    """
    for resource_hash in fileinfo['contained_resources']:
        if resource_hash in resource_clusters.keys():
            # Add file to cluster if resource hash cluster is present
            resource_clusters[resource_hash]['items'].add(fileinfo['sha256'])
        else:
            # Add new resource cluster if resource hash not present
            resource_clusters[resource_hash] = {
                'label': '',
                'learning_purity': 0,
                'items': set()
            }
            # Add this file to new cluster
            resource_clusters[resource_hash]['items'].add(fileinfo['sha256'])

def cluster_using_equal_values(key, fileinfo, cluster):
    """
    TODO: Dokumenter
    """
    if fileinfo[key] in cluster.keys():
        # If the value is present in the cluster keys,
        # add this file to the cluster
        cluster[fileinfo[key]]['items'].add(fileinfo['sha256'])
    else:
        # If value is not present in the cluster keys,
        # create new cluster and add this file to the new cluster
        cluster[fileinfo[key]] = {
            'label': '',
            'learning_purity': 0,
            'items': set()
        }
        cluster[fileinfo[key]]['items'].add(fileinfo['sha256'])

def cluster_using_tlsh(fileinfo, files, tlsh_clusters):
    """
    TODO: Dokumenter
    """
    threshold = TLSH_THRESHOLD
    best_score = threshold + 1
    best_cluster = None

    if TLSH_FAST_CLUSTERING:
        # If fast TLSH clustering (compare with first file in each cluster)
        for root_value in tlsh_clusters.keys():
            score = tlsh.diff(fileinfo['tlsh'], root_value)
            if score < best_score:
                best_score = score
                best_cluster = root_value
    else:
        # If not fast TLSH clustering (compare with all files)
        for otherfile in files.values():
            if (otherfile['tlsh'] is not None 
                    and fileinfo['sha256'] != otherfile['sha256']):
                score = tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])
                if score < best_score:
                    best_score = score
                    best_cluster = otherfile['tlsh_cluster']
    if best_cluster is not None:
        # If match was found, add to cluster
        tlsh_clusters[best_cluster]['items'].add(fileinfo['sha256'])
        fileinfo['tlsh_cluster'] = best_cluster
    else:
        # Create new tlsh cluster if no suitable cluster was found
        tlsh_clusters[fileinfo['tlsh']] = {
            'label': '',
            'learning_purity': 0,
            'items': set()
        }
        tlsh_clusters[fileinfo['tlsh']]['items'].add(fileinfo['sha256'])
        fileinfo['tlsh_cluster'] = fileinfo['tlsh']
        
        for otherfile in files.values():
            # For all files not in any tlsh cluster
            # TODO: Kan tlsh være blank? Hvis ikke, fjern første sjekk
            if (otherfile['tlsh']
                    and not otherfile['tlsh_cluster']
                    and fileinfo['sha256'] != otherfile['sha256']
                    and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])):
                # Add other files to this new cluster if they match
                tlsh_clusters[fileinfo['tlsh']]['items'].add(otherfile['sha256'])
                otherfile['tlsh_cluster'] = fileinfo['tlsh_cluster']

def label_clusters(files, feature_clusters):

    pass

def analyse_file_cluster(sha256hashes, files):

    families_in_cluster = {}
    cluster_size = len(sha256hashes)
    for sha256 in sha256hashes:
        family = files[sha256]['family']
        if family not in families_in_cluster.keys():
            families_in_cluster[family] = 1
        else:
            families_in_cluster[family] += 1
    # Retrieve the most common family (might be even, but should not matter)
    most_common_family = max(families_in_cluster, key=families_in_cluster.get)
    files_in_most_common = families_in_cluster[most_common_family]
    #num_in_other_families = cluster_size - files_in_most_common
    cluster_purity = files_in_most_common / cluster_size
    return cluster_purity, cluster_size, most_common_family, files_in_most_common


# TODO: Slett?
def not_bad_cluster(fileset, files):
    """
    Check if a cluster is not bad / unpure.
    This involves iterating through files where "training == True"
        and checking the how "pure" the cluster seems to be.
    Returns false if more than a certain ratio of the files belong to a different
        family than the majority if the cluster has more than a minimum number labelled files.
    """
    MINIMUM_PURITY = 0.8

    families = {}
    total_training_files = 0
    minimum_labelled_files = 1 / (1 - MINIMUM_PURITY)

    for sha256 in fileset:
        fileinfo = files[sha256]
        if fileinfo['training']:
            total_training_files += 1
            family = fileinfo['family']
            if family in families.keys():
                families[family] += 1
            else:
                families[family] = 1
    
    if total_training_files >= minimum_labelled_files:
        most_common_family = max(families, key=families.get)
        number_of_most_common = families[most_common_family]
        if number_of_most_common / total_training_files >= MINIMUM_PURITY:
            # If cluster purity is sufficiently pure, return true (not bad)
            return True
        else:
            # Or else, return false (cluster is bad)
            return False
    else:
        # If too few files, return true (not bad)
        return True
