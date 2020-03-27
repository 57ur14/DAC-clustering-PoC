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
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')
TLSH_THRESHOLD = config.getint('clustering', 'tlsh_threshold')
TLSH_FAST_CLUSTERING = config.getboolean('clustering', 'tlsh_fast_clustering')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')

# Decalare global variables
files = {}                  # Dictionary of of files
imphash_clusters = {}       # Dictionary of clusters where files have equal import hashes
icon_clusters = {}          # Dictionary of clusters where files have equal icon hashes
resource_clusters = {}      # Dictionary of clusters where files have equal resources contained
tlsh_clusters = {}          # Dictionary of tlsh clusters, identified by tlsh hash of root file
union_clusters = []         # List of clusters where files have been joined

def cluster_file(fileinfo):
    """
    Cluster the incoming file into existing clusters or create new clusters
    """
    union_cluster_index = None

    # TODO: Add checks if file already has been added to union cluster?
    # Is this possible? Don't know; Should check

    if len(fileinfo['contained_pe_files']) != 0:
        # If file contained another file and it could be clustered 
        # based on a child, cluster based on child
        union_cluster_index = cluster_on_contained_pe(fileinfo)

    if (union_cluster_index is None
            and (fileinfo['obfuscation']['type'] == 'none' or CLUSTER_PACKED_FILES == True)
            and fileinfo['imphash'] is not None
            and CLUSTER_WITH_IMPHASH == True):
        # Cluster using imphash if imphash is present 
        # and it is not obfuscated (fast)
        union_cluster_index = imphash_cluster(fileinfo)
    if (union_cluster_index is None
            and len(fileinfo['contained_resources']) != 0
            and CLUSTER_WITH_RESOURCES == True):
        # Cluster using contained resources if the
        # files contains any resources
        union_cluster_index = cluster_on_contained_resources(fileinfo)
    if (union_cluster_index is None
            and fileinfo['icon_hash'] is not None
            and CLUSTER_WITH_ICON == True):
        # Cluster using a hash of the icon - fast and should be 
        # suitable for both packed and non-packed samples 
        # (but slightly unaccurate)
        union_cluster_index = icon_cluster(fileinfo)
    
    if union_cluster_index is not None:
        # Add to cluster if suitable cluster was identified by 
        # the fast methods 
        union_clusters[union_cluster_index].add(fileinfo['sha256'])
        fileinfo['union_cluster'] = union_cluster_index
    elif ((CLUSTER_PACKED_FILES == True or fileinfo['obfuscation']['type'] == 'none')
            and CLUSTER_WITH_TLSH == True):
        # Cluster with TLSH if other features were not suitable, but TLSH is
        # Last resort
        tlsh_cluster(fileinfo)
    else:
        # If no suitable cluster was found, create new union cluster
        union_cluster_index = len(union_clusters)
        union_clusters.append(set([fileinfo['sha256']]))
        fileinfo['union_cluster'] = union_cluster_index
    

def imphash_cluster(fileinfo):
    """
    Attempt to cluster file based on imphash.
    Return the index of the union cluster the file should be placed into
    or None if the file does not fit in any union cluster.
    """
    if fileinfo['imphash'] in imphash_clusters:
        # Add to existing cluster if possible
        imphash_clusters[fileinfo['imphash']].add(fileinfo['sha256'])
        # Add to the same union cluster as the first file in the imphash cluster
        for sha256 in imphash_clusters[fileinfo['imphash']]:
            # Retrieve first item in set
            return files[sha256]['union_cluster']
    else:
        # Create new imphash cluster and union cluster if no matching cluster was found
        imphash_clusters[fileinfo['imphash']] = set([fileinfo['sha256']])
        return None


def icon_cluster(fileinfo):
    """
    Attempt to cluster file based on icon hash.
    Return the index of the union cluster the file should be placed into
    or None if the file does not fit in any union cluster.
    """
    if fileinfo['icon_hash'] in icon_clusters.keys():
        if not_bad_cluster(icon_clusters[fileinfo['icon_hash']]):
            icon_clusters[fileinfo['icon_hash']].add(fileinfo['sha256'])
            for sha256 in icon_clusters[fileinfo['icon_hash']]:
                # Retrieve first item in set
                return files[sha256]['union_cluster']
        else:
            return None
    else:
        icon_clusters[fileinfo['icon_hash']] = set([fileinfo['sha256']])
        return None

def cluster_on_contained_pe(fileinfo):
    """
    Attempt to add file to any cluster that a contained PE file is in.
    This is possible since unpacked files are sent to clustering before parent.
    """

    # Attempt to cluster based on children
    for sha256 in fileinfo['contained_pe_files']:
        # Prefer files that are not packed
        if (files[sha256]['obfuscation']['type'] == 'none'
                and files[sha256]['union_cluster'] is not None):
            return files[sha256]['union_cluster']
    
    if fileinfo['union_cluster'] is None:
        # If the file was not added to a union cluster yet
        # Attempt to cluster based on children that might be packed
        for sha256 in fileinfo['contained_pe_files']:
            if files[sha256]['union_cluster'] is not None:
                return files[sha256]['union_cluster']
    
    # Return None if no suitable cluster was found
    return None

def cluster_on_contained_resources(fileinfo):
    """
    Add to clusters for all contained resources.
    Return the index of the  most commonly shared union cluster 
    or None if the file does not fit in any union cluster.
    """
    union_cluster_of_files = []     # Store all suitable union clusters
    for resource_hash in fileinfo['contained_resources']:
        if resource_hash in resource_clusters.keys():
            if not_bad_cluster(resource_clusters[resource_hash]):
                resource_clusters[resource_hash].add(fileinfo['sha256'])
                for otherfile in resource_clusters[resource_hash]:
                    union_cluster_of_files.append(files[otherfile]['union_cluster'])
            else:
                continue
        else:
            resource_clusters[resource_hash] = set([fileinfo['sha256']])

    if len(union_cluster_of_files) != 0:
        # Find the most common union cluster among
        # the files in shared resource clusters
        return Counter(union_cluster_of_files).most_common(1)[0][0]
    else:
        return None

def tlsh_cluster(fileinfo):
    """
    Cluster file based on TrendMicro Locally Sensitive Hash
    Also add to union cluster if a suitable cluster is found
    or a new union cluster if no suitable cluster is found.

    This clustering involves only comparing to one "root node" in each clusters
    The root node is the first file added to a new cluster.
    When creating a new cluster, compare to files not present in any tlsh clusters.
    This type of clustering likely leads to lower accuracy, but increased speed.

    When comparing two TLSH hashes, a distance score is calculated.

    TODO: Should the file rather be compared to all other files?
    ...And should the threshold be further decreased?
    With a database of very many files it would probably be fine
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
        # If match was found, add to cluster and union cluster 
        # of first file in the tlsh cluster.
        for sha256 in tlsh_clusters[best_cluster]:
            fileinfo['union_cluster'] = files[sha256]['union_cluster']
            break
        union_clusters[fileinfo['union_cluster']].add(fileinfo['sha256'])
        # Must add to tlsh cluster after iterating over
        # set to avoid retrieving itself.
        tlsh_clusters[best_cluster].add(fileinfo['sha256'])
        fileinfo['tlsh_cluster'] = best_cluster
    else:
        # Create new tlsh cluster if no suitable cluster was found
        tlsh_clusters[fileinfo['tlsh']] = set([fileinfo['sha256']])
        fileinfo['tlsh_cluster'] = fileinfo['tlsh']
        # Also create new union cluster
        fileinfo['union_cluster'] = len(union_clusters)
        union_clusters.append(set([fileinfo['sha256']]))
        
        for otherfile in files.values():
            # For all files not in any tlsh cluster
            # TODO: Kan tlsh være blank?
            if (otherfile['tlsh'] is not None
                    and otherfile['tlsh_cluster'] is None
                    and fileinfo['sha256'] != otherfile['sha256']
                    and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])):
                # Add to this new tlsh cluster if they match
                tlsh_clusters[fileinfo['tlsh']].add(otherfile['sha256'])
                otherfile['tlsh_cluster'] = fileinfo['tlsh_cluster']
                # And also add to this new union cluster
                otherfile['union_cluster'] = fileinfo['union_cluster']
                union_clusters[fileinfo['union_cluster']].add(otherfile['sha256'])

def not_bad_cluster(fileset):
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
        if fileinfo['training'] == True:
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

def load_from_pickles():
    global files
    global imphash_clusters
    global icon_clusters
    global resource_clusters
    global tlsh_clusters
    global union_clusters

    if os.path.exists('pickles/'):
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

def save_to_pickles():
    try:
        os.mkdir('pickles')
    except FileExistsError:
        pass

    # Write results to pickles to allow further processing
    with open('pickles/files.pkl', 'wb') as picklefile:
        pickle.dump(files, picklefile)
    with open('pickles/imphash_clusters.pkl', 'wb') as picklefile:
        pickle.dump(imphash_clusters, picklefile)
    with open('pickles/icon_clusters.pkl', 'wb') as picklefile:
        pickle.dump(icon_clusters, picklefile)
    with open('pickles/tlsh_clusters.pkl', 'wb') as picklefile:
        pickle.dump(tlsh_clusters, picklefile)
    with open('pickles/resource_clusters.pkl', 'wb') as picklefile:
        pickle.dump(resource_clusters, picklefile)
    with open('pickles/union_clusters.pkl', 'wb') as picklefile:
        pickle.dump(union_clusters, picklefile)