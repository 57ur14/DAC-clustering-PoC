#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

def labelling_stats(cluster):
    total = 0
    unlabelled = 0
    num_packed = 0

    for sha in cluster['items']:
        if files[sha]['incoming']:
            total += 1
            if files[sha]['given_label'] is None:
                unlabelled += 1
            if files[sha]['obfuscation'] is not None:
                num_packed += 1
    return total, unlabelled, num_packed

def total_files_to_label(files):
    """
    TODO: Dokumenter
    """
    total = 0
    for fileinfo in files.values():
        if fileinfo['incoming'] and fileinfo['given_label'] is None:
            total += 1
    return total

def evaluate_quality(cluster, cluster_list):
    """
    TODO: Dokumenter
    """
    incoming, unlabelled, packed = labelling_stats(cluster)
    labelled = incoming - unlabelled
    
    if (incoming == 0
            or cluster['label'] is not None 
            or unlabelled < labelled):
        return
    #elif cluster['packed_incoming'] == cluster['total_incoming']:
    # If the above statement is not true, but the number of packed
    # files is equal to the size of the cluster, the cluster
    # is likely of poor quality.
    #    continue
    else:
        cluster['total_incoming'] = incoming
        cluster['packed_incoming'] = packed
        cluster['unlabelled_files'] = unlabelled
        cluster['labelled_files'] = labelled
        cluster_list.append(cluster)

def get_unlabelled(cluster):
    return cluster['unlabelled_files']

def get_label_from_in_depth_analysis(fileinfo):
    """
    TODO: Dokumenter
    """
    return fileinfo['family']

def label_clusters_of_file(fileinfo, files, clusters):
    labelled = 0
    correctly = 0
    incorrectly = 0
    results = []

    if fileinfo['imphash'] is not None:
        cluster = clusters['imphash_clusters'][fileinfo['imphash']]
        if cluster['label'] is None:
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))

    if fileinfo['icon_hash'] is not None:
        cluster = clusters['icon_clusters'][fileinfo['icon_hash']]
        if cluster['label'] is None:
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))
    for sha in fileinfo['contained_resources']:
        cluster = clusters['resource_clusters'][sha]
        if cluster['label'] is None:
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))
    if fileinfo['tlsh_cluster'] is not None:
        cluster = clusters['tlsh_clusters'][fileinfo['tlsh_cluster']]
        if cluster['label'] is None:
            results.append(label_cluster_and_files(fileinfo['given_label'], cluster, files, clusters))

    for l, c, i in results:
        labelled += l
        correctly += c
        incorrectly += i
    
    return labelled, correctly, incorrectly

def label_cluster_and_files(label, cluster, files, clusters):
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

if __name__ == '__main__' and load_from_pickles('pickles/validated/', True):
    num_files_to_label = total_files_to_label(files)
    files_analysed_in_depth = 0

    print("Number of files to label before: " + str(num_files_to_label))
    
    # Measure how correc the labelling performed
    # through induction is.
    correctly_labelled = 0
    mislabelled = 0

    still_more = True

    while still_more:
        cluster_list = []

        for cluster_type in clusters.values():
            for cluster in cluster_type.values():
                evaluate_quality(cluster, cluster_list)
        
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