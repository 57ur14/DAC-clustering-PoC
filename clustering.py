# -*- coding: utf-8 -*-
"""
clustering - a module for clustering and labelling files

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae

Dependencies:
* tlsh
"""

import configparser
import os
import pickle

import tlsh

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('general', 'print_progress')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')
TLSH_THRESHOLD = config.getint('clustering', 'tlsh_threshold')
TLSH_FAST_CLUSTERING = config.getboolean('clustering', 'tlsh_fast_clustering')
CLUSTER_PACKED_FILES = config.getboolean('clustering', 'cluster_with_packed_files')
CLUSTER_WITH_CONTAINED_PE = config.getboolean('clustering', 'cluster_with_contained_pe')
LABEL_ON_CONTAINED_PE = config.getboolean('clustering', 'label_on_contained_pe')
CLUSTER_WITH_VHASH = config.getboolean('clustering', 'cluster_with_vhash')

def cluster_files(files, clusters):
    """
    Create clusters based on file features
    """

    for sha256 in files.keys():
        # Iterate over all files and cluster files
        fileinfo = files[sha256]

        if fast_cluster_file(fileinfo, clusters):
            fileinfo['fast_clustered'] = True
        else:
            # If file was not fast clustered, cluster using slow features
            slow_cluster_file(fileinfo, files, clusters)
            fileinfo['slow_clustered'] = True
       

def cluster_file(fileinfo, files, clusters):
    """
    Cluster a provided file. Attempt to cluster using fast features
    and cluster using slow features if fast clustering was unsuccessful.
    
    Returns True if file was clustered using fast features / clustering
    methods and False if the file was clustered using slow features/methods.

    Used during validation when files are clustered in real-time.
    TODO: Update cluster purity and labels after clustering this file?
    """
    if fast_cluster_file(fileinfo, clusters, True):
        fileinfo['fast_clustered'] = True
        return True
    else:
        # If file was not fast clustered, cluster using slow features
        slow_cluster_file(fileinfo, files, clusters)
        fileinfo['slow_clustered'] = True
        return False


def fast_cluster_file(fileinfo, clusters, only_successful_if_labelled_cluster=False):
    """
    Attempt to cluster a file using features that allow fast
    clustering, such as imphash, contained resources and icon hash
    Returns False if the file could not be clustered with fast features
    Returns True if the file could be clustered with fast features.

    If only_successful_if_labelled_cluster is set to true,
    this function will only return True if the file could be clustered
    with fast features and the file was added to an existing cluster
    that has a label.    
    """
    successfully_clustered = False

    if CLUSTER_WITH_VHASH and fileinfo['vhash']:
        # Cluster with vhash if supposed to an file has a vhash
        if (cluster_using_equal_values('vhash', fileinfo, clusters['vhash_clusters'])
                or not only_successful_if_labelled_cluster):
            successfully_clustered = True


    if CLUSTER_WITH_RESOURCES and fileinfo['contained_resources']:
        # Cluster with resources if file contained resources
        if (cluster_on_contained_resources(fileinfo, clusters['resource_clusters'])
                or not only_successful_if_labelled_cluster):
            successfully_clustered = True

    if CLUSTER_WITH_ICON and fileinfo['icon_hash']:
        # Cluster using a hash of the icon
        if (cluster_using_equal_values('icon_hash', fileinfo, clusters['icon_clusters'])
                or not only_successful_if_labelled_cluster):
            successfully_clustered = True

    if fileinfo['obfuscation'] is None or CLUSTER_PACKED_FILES:
        # If file is not obfuscated or the configuration
        # specifies that obfuscated files should be packed

        if CLUSTER_WITH_IMPHASH and fileinfo['imphash']:
            # Cluster with imphash
            if (cluster_using_equal_values('imphash', fileinfo, clusters['imphash_clusters'])
                    or not only_successful_if_labelled_cluster):
                successfully_clustered = True
    return successfully_clustered

def slow_cluster_file(fileinfo, files, clusters):
    # Cluster with slow methods only if not yet clustered
    if CLUSTER_WITH_TLSH and fileinfo['tlsh']:
        cluster_using_tlsh(fileinfo, files, clusters['tlsh_clusters'])

def cluster_on_contained_resources(fileinfo, resource_clusters):
    """
    Attempt to cluster a file based on resources that
    have been unpacked from the file.
    Returns True if file was added to an existing cluster
    with a label and false if not.
    """
    successfully_clustered = False
    for resource_hash in fileinfo['contained_resources']:
        if resource_hash in resource_clusters.keys():
            # Add file to cluster if resource hash cluster is present
            resource_clusters[resource_hash]['items'].add(fileinfo['sha256'])
            if resource_clusters[resource_hash]['label'] is not None:
                successfully_clustered = True
        else:
            # Add new resource cluster if resource hash not present
            resource_clusters[resource_hash] = {
                'label': None,
                'training_purity': 0,
                'items': set()
            }
            # Add this file to new cluster
            resource_clusters[resource_hash]['items'].add(fileinfo['sha256'])
    return successfully_clustered

def cluster_using_equal_values(key, fileinfo, cluster):
    """
    Cluster a file by checking for equal values in a hash table.
    If value was found in hash table, add to the cluster identified
    by the value.
    If no cluster was found for the provided value, create a new
    cluster identified by the value.
    Returns True if the file was added to an existing cluster
    with a label and False if not.
    """
    if fileinfo[key] in cluster.keys():
        # If the value is present in the cluster keys,
        # add this file to the cluster
        cluster[fileinfo[key]]['items'].add(fileinfo['sha256'])
        if cluster[fileinfo[key]]['label'] is not None:
            return True
    else:
        # If value is not present in the cluster keys,
        # create new cluster and add this file to the new cluster
        cluster[fileinfo[key]] = {
            'label': None,
            'training_purity': 0,
            'items': set()
        }
        cluster[fileinfo[key]]['items'].add(fileinfo['sha256'])
        return False

def cluster_using_tlsh(fileinfo, files, tlsh_clusters):
    """
    Cluster a file using tlsh by calcualting a distance score
    between this file and all other files. Add this file to the 
    cluster of the file that was the best match.
    If no file was found to match, create a new cluster.
    Returns True if this file was added to an existing cluster
    with a label and False if not.
    """
    best_score = TLSH_THRESHOLD + 1
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
                # Calculate distance
                score = tlsh.diff(fileinfo['tlsh'], otherfile['tlsh'])
                # If distance is lower than previous best
                if score < best_score:
                    # Store new values
                    best_score = score
                    best_cluster = otherfile['tlsh_cluster']
    if best_cluster is not None:
        # If matching file/cluster was found, add to cluster
        tlsh_clusters[best_cluster]['items'].add(fileinfo['sha256'])
        fileinfo['tlsh_cluster'] = best_cluster
        if tlsh_clusters[best_cluster]['label'] is not None:
            return True
    else:
        # Create new tlsh cluster if no suitable cluster was found
        tlsh_clusters[fileinfo['tlsh']] = {
            'label': None,
            'training_purity': 0,
            'items': set()
        }
        tlsh_clusters[fileinfo['tlsh']]['items'].add(fileinfo['sha256'])
        fileinfo['tlsh_cluster'] = fileinfo['tlsh']
        
        if TLSH_FAST_CLUSTERING:
            # If fast clustering, check distance to all files not
            # in any cluster (since they have not been compared
            # to this new root node and might match).
            for otherfile in files.values():
                # For all files not in any tlsh cluster
                if (otherfile['tlsh']
                        and not otherfile['tlsh_cluster']
                        and fileinfo['sha256'] != otherfile['sha256']
                        and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh']) <= TLSH_THRESHOLD):
                    # Add other files to this new cluster if they match
                    tlsh_clusters[fileinfo['tlsh']]['items'].add(otherfile['sha256'])
                    otherfile['tlsh_cluster'] = fileinfo['tlsh_cluster']
        return False

def label_clusters(files, clusters):
    """
    Iterate over all cluster types and label the clusters
    """
    for feature_type in clusters.keys():
        # Label all clusters for all feature types
        label_clusters_of_specific_feature(clusters[feature_type], files)

def label_clusters_of_specific_feature(feature_clusters, files):
    """
    Attempt to label all clusters created with a specific feature.
    TODO: Attempt with different thresholds for minimum purity
    """
    MINIMUM_PURITY = 0.8
    if MINIMUM_PURITY == 1:
        MINIMUM_REQUIRED_FILES = 1
    else:
        MINIMUM_REQUIRED_FILES = 1 / (1 - MINIMUM_PURITY)
    ABSOLUTE_MINIMUM = 0.51
    
    # Mark clusters with family and purity
    # Only sufficiently pure families with a clear label should be used to label testing files.
    for key in feature_clusters.keys():
        cluster_purity, cluster_size, most_common_family, _ = analyse_file_cluster(feature_clusters[key]['items'], files, True)
        if (cluster_purity >= MINIMUM_PURITY 
                or (cluster_size < MINIMUM_REQUIRED_FILES 
                and cluster_purity >= ABSOLUTE_MINIMUM)):
            # If cluster is sufficiently pure or there are few 
            # files in the cluster (but the purity is at least 51%),
            # label the cluster with the name of the most common family.
            feature_clusters[key]['label'] = most_common_family
            feature_clusters[key]['training_purity'] = cluster_purity
        # If cluster cannot be labelled, the label will remain
        # as the default value (None)

def analyse_file_cluster(sha256hashes, files, only_incoming=True):
    """
    Analyse a cluster with files to calcualte the cluster purity and
    cluster size, identify the most common family and number
    of files in said family.
    Returns a tuple consisting of these values
    If only_incoming is set to false, the function will take unpacked
    files into the calculation.
    """
    families_in_cluster = {}
    cluster_size = 0
    for sha256 in sha256hashes:
        fileinfo = files[sha256]
        # Only analyse incoming files (unpacked files are not relevant)
        if fileinfo['incoming'] or only_incoming == False:
            #print(fileinfo)
            cluster_size += 1
            if fileinfo['family'] not in families_in_cluster.keys():
                families_in_cluster[fileinfo['family']] = 1
            else:
                families_in_cluster[fileinfo['family']] += 1
    if cluster_size == 0:
        return 0, 0, '', 0
    
    # Retrieve the most common family (might be even, but should not matter)
    most_common_family = max(families_in_cluster, key=families_in_cluster.get)
    files_in_most_common = families_in_cluster[most_common_family]
    #num_in_other_families = cluster_size - files_in_most_common
    cluster_purity = files_in_most_common / cluster_size
    return cluster_purity, cluster_size, most_common_family, files_in_most_common

def label_file(fileinfo, files, clusters):
    """
    Label a file based on the labels of 
    clusters this file belongs to.
    """
    labels = {}
    feature_keys = [
        ('imphash', 'imphash_clusters', False),
        ('contained_resources', 'resource_clusters', True),
        ('icon_hash', 'icon_clusters', False),
        ('tlsh_cluster', 'tlsh_clusters', False)
    ]
    if CLUSTER_WITH_VHASH:
        feature_keys.append(('vhash', 'vhash_clusters', False))

    for row in feature_keys:
        fileinfo_key, cluster_key, is_a_set = row
        label, purity = get_label_on_feature(fileinfo, fileinfo_key, clusters[cluster_key], is_a_set)
        if label is not None:
            if label in labels.keys():
                labels[label] += purity
            else:
                labels[label] = purity
    if labels:
        fileinfo['given_label'] = max(labels, key=labels.get)
    elif LABEL_ON_CONTAINED_PE:
        # Attempt to label on contained PE files 
        # if no label had been found yet.
        fileinfo['given_label'] = label_file_on_contained_pe(fileinfo, files)

def get_label_on_feature(fileinfo, key, feature_clusters, is_a_set=False):
    """
    Check if this file is placed in a cluster based on the provided
    feature, and if so, return the label given to the cluster (or None
    if the cluster does not have a label).
    If is_a_set is set to True, iterate over the feature as a set
    containing keys/indexes to the clusters.
    """
    if not fileinfo[key]:
        # Return None if no cluster index was found
        return None, None
    if is_a_set:
        # if fileinfo[key] is a set of multiple items, 
        # iterate over all potential clusters
        labels = {}
        for value in fileinfo[key]:
            label = feature_clusters[value]['label']
            if label is not None:
                # Store that an occurrence of the current label was found
                if label in labels.keys():
                    labels[label] += feature_clusters[value]['training_purity']
                else:
                    labels[label] = feature_clusters[value]['training_purity']
        if labels:
            # Return most common label if any labels were found
            # and a number indicating how many clusters had
            # this label and the cluster purity
            most_common_label = max(labels, key=labels.get)
            return most_common_label, labels[most_common_label]
        else:
            # Return None if no labels were found
            return None, None
    else:
        # Return label (or None if no label on cluster)
        # and a number indicating the cluster purity
        return feature_clusters[fileinfo[key]]['label'], feature_clusters[fileinfo[key]]['training_purity']

def label_file_on_contained_pe(fileinfo, files):
    """
    Attempt to label file based on the label of
    files unpacked from this file.
    Returns the label or None if the file was not
    unpacked to any files or the unpacked files
    did not have any labels.
    """
    if fileinfo['contained_pe_files']:
        labels = {}
        for sha in fileinfo['contained_pe_files']:
            label = files[sha]['given_label']
            if label is not None:
                if label in labels.keys():
                    # TODO: Are all contained files
                    # equally trustworthy?
                    # Include a quality measure on files?
                    labels[label] += 1
                else:
                    labels[label] = 1
        if labels:
            # Return most common family among contained pe files
            return max(labels, key=labels.get)
    # Return None if no contained files or files did not have labels
    return None

def analyse_clustered_files(files):
    """
    Analyse all files and return a dictionary containing
    statistics describing the speend and quality of feature
    extraction and clustering.
    """
    total_pe_files = 0
    incoming_pe_files = 0
    unpacked_pe_files = 0
    incoming_unpacked_to_nonpacked = 0
    obfuscated_pe_files = 0
    obfuscated_incoming_pe = 0
    obfuscated_unpacked_pe = 0
    fast_clustered_files = 0
    fast_clustered_incoming = 0
    slow_clustered_files = 0
    slow_clustered_incoming = 0

    for fileinfo in files.values():
        total_pe_files += 1

        if fileinfo['fast_clustered']:
            fast_clustered_files += 1
        if fileinfo['slow_clustered']:
            slow_clustered_files += 1
        
        if fileinfo['incoming']:
            incoming_pe_files += 1
            if fileinfo['unpacks_to_nonpacked_pe']:
                incoming_unpacked_to_nonpacked += 1
            if fileinfo['obfuscation'] is not None:
                obfuscated_pe_files += 1
                obfuscated_incoming_pe += 1
            if fileinfo['fast_clustered']:
                fast_clustered_incoming += 1
            if fileinfo['slow_clustered']:
                slow_clustered_incoming += 1
        else:
            unpacked_pe_files += 1
            if fileinfo['obfuscation'] is not None:
                obfuscated_pe_files += 1
                obfuscated_unpacked_pe += 1
    
    return {
        'total_pe_files': total_pe_files,
        'incoming_pe_files': incoming_pe_files,
        'unpacked_pe_files': unpacked_pe_files,
        'incoming_unpacked_to_nonpacked': incoming_unpacked_to_nonpacked,
        'obfuscated_pe_files': obfuscated_pe_files,
        'obfuscated_incoming_pe': obfuscated_incoming_pe,
        'obfuscated_unpacked_pe': obfuscated_unpacked_pe,
        'fast_clustered_files': fast_clustered_files,
        'fast_clustered_incoming': fast_clustered_incoming,
        'slow_clustered_files': slow_clustered_files,
        'slow_clustered_incoming': slow_clustered_incoming
    }

def analyse_clusters(files, clusters):
    """
    Analyse all clusters and return a dicionary containing statistics
    describing the speed and quality of the clustering.
    """
    stats = {
        'imphash_cluster_stats': analyse_clusters_on_feature(files, clusters['imphash_clusters']),
        'icon_cluster_stats': analyse_clusters_on_feature(files, clusters['icon_clusters']),
        'resource_cluster_stats': analyse_clusters_on_feature(files, clusters['resource_clusters']),
        'tlsh_cluster_stats': analyse_clusters_on_feature(files, clusters['tlsh_clusters'])
    }
    if CLUSTER_WITH_VHASH:
        stats['vhash_cluster_stats'] = analyse_clusters_on_feature(files, clusters['vhash_clusters']),
    return stats

def analyse_clusters_on_feature(files, feature_clusters):
    """
    Analyse the provided clusters and return a dictionary containing
    statistics describing the speed and quality of the clustering.
    """
    mean_purity = 0
    mean_size = 0
    number_of_clusters = 0
    total_incoming_files_in_clusters = 0
    
    for key in feature_clusters.keys():
        for sha in feature_clusters[key]['items']:
            if files[sha]['incoming']:
                total_incoming_files_in_clusters += 1
        cluster_purity, cluster_size, _, _ = analyse_file_cluster(feature_clusters[key]['items'], files, True)
        if cluster_size:
            mean_purity += cluster_purity
            mean_size += cluster_size
            number_of_clusters += 1
    
    if number_of_clusters:
        mean_purity = mean_purity / number_of_clusters
        mean_size = mean_size / number_of_clusters
    
    return {
        'mean_purity': mean_purity,
        'mean_size': mean_size,
        'total_incoming_files_in_clusters': total_incoming_files_in_clusters,
        'number_of_clusters': number_of_clusters
    }

