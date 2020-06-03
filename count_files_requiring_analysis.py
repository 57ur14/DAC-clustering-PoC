#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
count_files_requiring_analysis - a script for counting the number of files 
    that would need in-depth analysis if representative files are analysed.

Part of D&C-Clustering-POC

Copyright (c) 2020 Sturla Høgdahl Bae
"""

import os
import pickle
from multiprocessing import Process, Manager

files = {}
clusters = {
    'imphash_clusters': {},
    'icon_clusters': {},
    'resource_clusters': {},
    'tlsh_clusters': {}
}

def load_from_pickles(folder, load_clusters=False):
    """
    Load data from pickles
    Folder should be the path to a folder where the 
        files "files.pkl" and "clusters.pkl" will be stored.
        Suggested values:
            pickles/extracted/
            pickles/clustered/
            pickles/validated/
    If load_clusters is True, clusters will also be loaded
    Returns False on failure to load pickles and True on success
    """
    global files
    global clusters

    files_path = os.path.join(folder, 'files.pkl')
    clusters_path = os.path.join(folder, 'clusters.pkl')

    if not os.path.exists(files_path):
        print("Files pickle not found. Perform feature extraction before attempting to cluster / validate.")
        return False
    else:
        with open(files_path, 'rb') as picklefile:
            files = pickle.load(picklefile)
    if load_clusters and not os.path.exists(clusters_path):
        print("Clusters pickle not found. Perform training before attempting to validate.")
        return False
    elif load_clusters:
        with open(clusters_path, 'rb') as picklefile:
            clusters = pickle.load(picklefile)
    return True

def total_files_to_label(files):
    """
    Identify the number of files that do not have a label. 
    Returns the number of unlabelled, incoming files.
    """
    total = 0
    for fileinfo in files.values():
        if fileinfo['incoming'] and fileinfo['given_label'] is None:
            total += 1
    return total

def fill_cluster_details(cluster, files):
    """
    Count the number of incoming files, packed incoming files,
    unlabelled incoming and labelled incoming files.
    Add these properties to the cluster.
    """
    incoming = 0
    unlabelled = 0
    packed = 0

    for sha in cluster['items']:
        if files[sha]['incoming']:
            incoming += 1
            if files[sha]['given_label'] is None:
                unlabelled += 1
            if files[sha]['obfuscation'] is not None:
                packed += 1

    labelled = incoming - unlabelled

    cluster['total_incoming'] = incoming
    cluster['packed_incoming'] = packed
    cluster['unlabelled_files'] = unlabelled
    cluster['labelled_files'] = labelled

def is_good_quality(cluster):
    """
    Evaluate the quality of a cluster.
    Returns True of the quality is evaluated to be good,
    and False if the quality is evaluated to be poor.
    """
    
    if (cluster['total_incoming'] != 0
            and cluster['label'] is None 
            and cluster['unlabelled_files'] > cluster['labelled_files']):
        return True
    else:
        return False
        

def get_unlabelled(cluster):
    """
    Return the value contained in the key "unlabelled_files"
    """
    return cluster['unlabelled_files']

def get_label_from_in_depth_analysis(fileinfo):
    """
    Simulated in-depth analysis.
    Returns the real label of the file.
    """
    return fileinfo['family']

def label_clusters_of_file(fileinfo, files, clusters):
    """
    Iterate over all clusters a file is part of, and which
    do not have a label. If a cluster is of good quality,
    use the label of the given file to label the cluster
    and the files contained in the file.
    """
    labelled = 0
    correctly = 0
    incorrectly = 0
    results = []

    if fileinfo['imphash'] is not None:
        cluster = clusters['imphash_clusters'][fileinfo['imphash']]
        if is_good_quality(cluster):
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))

    if fileinfo['icon_hash'] is not None:
        cluster = clusters['icon_clusters'][fileinfo['icon_hash']]
        if is_good_quality(cluster):
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))
    for sha in fileinfo['contained_resources']:
        cluster = clusters['resource_clusters'][sha]
        if is_good_quality(cluster):
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))
    if fileinfo['tlsh_cluster'] is not None:
        cluster = clusters['tlsh_clusters'][fileinfo['tlsh_cluster']]
        if is_good_quality(cluster):
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))

    for l, c, i in results:
        labelled += l
        correctly += c
        incorrectly += i
    
    return labelled, correctly, incorrectly

def label_cluster_and_files(label, cluster, files, clusters):
    """
    Use the provided label to label a given cluster.
    Then iterate over files in the cluster. If a file
    does not have a label, label the file and propagate
    labelling to the clusters of that file.
    """
    l = 0
    c = 0
    i = 0
    
    cluster['label'] = label
    for sha in cluster['items']:
        fileinfo = files[sha]
        if fileinfo['given_label'] is None:
            fileinfo['given_label'] = label
            if fileinfo['incoming']:
                if fileinfo['given_label'] == fileinfo['family']:
                    c += 1
                else:
                    i += 1
                l += 1
                
                l2, c2, i2 = label_clusters_of_file(fileinfo, files, clusters)
                l += l2
                c += c2
                i += i2
    return l, c, i

if __name__ == '__main__':
    successfully_loaded = load_from_pickles('pickles/validated/', True)
    if not successfully_loaded:
        print("Run training (-T or -E + -C) and validation (-V) first")       
        raise SystemExit
    
    num_files_to_label = total_files_to_label(files)
    files_analysed_in_depth = 0
    correctly_labelled = 0
    mislabelled = 0

    print("Number of files to label before: " + str(num_files_to_label))

    still_more = True

    while still_more:
        cluster_list = []

        for cluster_type in clusters.values():
            for cluster in cluster_type.values():
                fill_cluster_details(cluster, files)
                if is_good_quality(cluster):
                    cluster_list.append(cluster)
        
        cluster_list.sort(key=get_unlabelled)

        if cluster_list:
            prioritised = cluster_list.pop()
        else:
            break

        representative = None
        for sha in prioritised['items']:
            fileinfo = files[sha]
            if fileinfo['incoming']:
                if fileinfo['obfuscation'] is None:
                    # Representative file should ideally
                    # not be obfuscated
                    representative = fileinfo
                    break
                elif representative is None:
                    # If no non-obfuscated file was available,
                    # use an obfuscated file as representative file.
                    representative = fileinfo

        # If an representative file was identified (should be true)
        if representative is not None:
            label = get_label_from_in_depth_analysis(representative)
            representative['given_label'] = label
            files_analysed_in_depth += 1
            num_files_to_label -= 1
            
            labelled, correctly, incorrectly = label_clusters_of_file(representative, files, clusters)
            
            num_files_to_label -= labelled
            correctly_labelled += correctly
            mislabelled += incorrectly
            
        if not cluster_list:
            still_more = False

    total_in_depth_analysis = files_analysed_in_depth + num_files_to_label

    print("Files sent to simulated in-depth analysis: " + str(files_analysed_in_depth))
    print("Files correctly labelled through induction: " + str(correctly_labelled))
    print("Files incorrectly labelled through induction: " + str(mislabelled))
    print("Number of files to label after: " + str(num_files_to_label))
    print("Files to send to in-depth analysis in total: " + str(total_in_depth_analysis))