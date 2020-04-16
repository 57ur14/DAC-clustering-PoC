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

def cluster_files(files, clusters):
    """
    Create clusters based on file features
    """

    for sha256 in files.keys():
        # Iterate over all files and cluster files
        # that can be clustered with fast methods
        fileinfo = files[sha256]
        fast_cluster_file(fileinfo, clusters)
    
    for sha256 in files.keys():
        # Iterate over files again to cluster the remaining files
        fileinfo = files[sha256]
        if not fileinfo['fast_clustered']:
            # If the file has not been clustered with fast properties
            if CLUSTER_WITH_CONTAINED_PE and fileinfo['contained_pe_files']:
                # Attempt to cluster the file on contained PE files
                cluster_on_contained_files(fileinfo, files, clusters)
            if not fileinfo['fast_clustered']:
                # If still not fast clustered, cluster using slow features
                slow_cluster_file(fileinfo, files, clusters)

def cluster_file(fileinfo, files, clusters):
    """
    TODO: Dokumenter
    Benyttes under real-time clustering for å clustere én fil
    
    TODO: Bør filer under validering clusteres med trege metoder
    dersom de er alene i alle clustere dannet med raske metoder?
    Altså kun "fast clusteret" hvis de faktisk havner sammen med andre filer
    """
    fast_cluster_file(fileinfo, clusters)
    if not fileinfo['fast_clustered']:
        # If the file has not been clustered with fast properties
        if CLUSTER_WITH_CONTAINED_PE and fileinfo['contained_pe_files']:
            # Attempt to cluster the file on contained PE files
            cluster_on_contained_files(fileinfo, files, clusters)
        if not fileinfo['fast_clustered']:
            # If still not fast clustered, cluster using slow features
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

def cluster_on_contained_files(fileinfo, files, clusters):
    """
    TODO: Dokumenter
    """
    for contained in fileinfo['contained_pe_files']:
        otherfile = files[contained]
        # Iterate over contained files
        if not otherfile['fast_clustered']:
            # Before clustering the contained file, recursively
            # fast cluster the files contained in this the current file
            cluster_on_contained_files(otherfile, files, clusters)
        if otherfile['fast_clustered']:
            # If the contained file has been fast clustered 
            # (based on the files contained inside of it),
            # fast cluster this file based on the contained file
            if cluster_on_contained_file(fileinfo, otherfile, files, clusters):
                return True
    return False

def cluster_on_contained_file(original, contained, files, clusters):
    """
    TODO: Dokumenter
    TODO: Sjekk logikken til denne metoden.
    TODO: Slett denne funksjonen og heller bare label filer basert på utpakkede filer?
    Under validering kan man sjekke om noen utpakkede filer har fått en label!
    Vil forelderen egentlig kunne vite hvilken cluster den er i?
    """
    # Create a new "fake" fileinfo.
    # It has the features of the contained file, but
    # the sha256 checksum of the original file
    # so that this file's checksum is added to the clusters
    # the contained file would be added to
    fake_info = contained.copy()
    fake_info['sha256'] = original['sha256']
    fake_info['incoming'] = True
    fast_cluster_file(fake_info, clusters)
    if fake_info['fast_clustered']:
        original['fast_clustered'] = True
        return True
    else:
        slow_cluster_file(fake_info, files, clusters)
        if fake_info['slow_clustered']:
            original['fast_clustered'] = True
            return True
    return False

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
                'label': None,
                'training_purity': 0,
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
            'label': None,
            'training_purity': 0,
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
            'label': None,
            'training_purity': 0,
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
                    and tlsh.diff(fileinfo['tlsh'], otherfile['tlsh']) <= threshold):
                # Add other files to this new cluster if they match
                tlsh_clusters[fileinfo['tlsh']]['items'].add(otherfile['sha256'])
                otherfile['tlsh_cluster'] = fileinfo['tlsh_cluster']

def label_clusters(files, clusters):
    """
    TODO: Dokumenter
    """
    for feature_type in clusters.keys():
        # Label all clusters for all feature types
        label_clusters_of_specific_feature(clusters[feature_type], files)

def label_clusters_of_specific_feature(feature_clusters, files):
    """
    TODO: Dokumenter
    """
    MINIMUM_PURITY = 0.8
    MINIMUM_REQUIRED_FILES = 1 / (1 - MINIMUM_PURITY)
    ABSOLUTE_MINIMUM = 0.51
    
    # Mark clusters with family and purity
    # Only sufficiently pure families with a clear label should be used to label testing files.
    for key in feature_clusters.keys():
        cluster_purity, cluster_size, most_common_family, files_in_most_common = analyse_file_cluster(feature_clusters[key]['items'], files, True)
        if (cluster_purity > MINIMUM_PURITY 
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
    TODO: Dokumenter
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
    TODO: Dokumenter
    """
    labels = {}
    feature_keys = [
        ('imphash', 'imphash_clusters', False),
        ('contained_resources', 'resource_clusters', True),
        ('icon_hash', 'icon_clusters', False),
        ('tlsh_cluster', 'tlsh_clusters', False)
    ]

    for row in feature_keys:
        fileinfo_key, cluster_key, is_a_set = row
        label = get_label_on_feature(fileinfo, fileinfo_key, clusters[cluster_key], is_a_set)
        if label is not None:
            if label in labels.keys():
                labels[label] += 1
            else:
                labels[label] = 1
    if labels:
        fileinfo['given_label'] = max(labels, key=labels.get)
    elif LABEL_ON_CONTAINED_PE:
        # Attempt to label on contained PE files 
        # if no label had been found yet.
        fileinfo['given_label'] = label_file_on_contained_pe(fileinfo, files)

def get_label_on_feature(fileinfo, key, feature_clusters, is_a_set=False):
    """
    TODO: Dokumenter
    """
    if not fileinfo[key]:
        # Return None if no cluster index was found
        return None
    if is_a_set:
        # if fileinfo[key] is a set of multiple items, 
        # iterate over all potential clusters
        labels = {}
        for value in fileinfo[key]:
            label = feature_clusters[value]['label']
            if label is not None:
                # Set label and return True if label was found
                if label in labels.keys():
                    labels[label] += 1
                else:
                    labels[label] = 1
        if labels:
            # Return most common label if any labels were found
            return max(labels, key=labels.get)
        else:
            # Return None if no labels were found
            return None
    else:
        # Return label (or None if no label on cluster)
        return feature_clusters[fileinfo[key]]['label']

def label_file_on_contained_pe(fileinfo, files):
    """
    TODO: Dokumenter
    """
    labels = {}
    if fileinfo['contained_pe_files']:
        for sha in fileinfo['contained_pe_files']:
            label = files[sha]['given_label']
            if label is not None:
                if label in labels.keys():
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
    TODO: Dokumenter
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
    TODO: Dokumenter
    """
    return {
        'imphash_cluster_stats': analyse_clusters_on_feature(files, clusters['imphash_clusters']),
        'icon_cluster_stats': analyse_clusters_on_feature(files, clusters['icon_clusters']),
        'resource_cluster_stats': analyse_clusters_on_feature(files, clusters['resource_clusters']),
        'tlsh_cluster_stats': analyse_clusters_on_feature(files, clusters['tlsh_clusters'])
    }

def analyse_clusters_on_feature(files, feature_clusters):
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

