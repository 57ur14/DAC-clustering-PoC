#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import pickle

import clustering

config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
CLUSTER_WITH_IMPHASH = config.getboolean('clustering', 'cluster_with_imphash')
CLUSTER_WITH_ICON = config.getboolean('clustering', 'cluster_with_icon')
CLUSTER_WITH_RESOURCES = config.getboolean('clustering', 'cluster_with_resources')
CLUSTER_WITH_CONTAINED_PE = config.getboolean('clustering', 'cluster_with_contained_pe')
CLUSTER_WITH_TLSH = config.getboolean('clustering', 'cluster_with_tlsh')


files = {}                  # Dictionary of of files
clusters = {}               # Dictionary of clusters
stats = {
    'incoming_pe': 0,
    'unpacked_pe_files': 0,
    'successfully_unpacked_incoming': 0,
    'total_pe_files': 0,
    'total_obfuscated_pe_files': 0,
    'obfuscated_unpacked_pe_files': 0,
    'obfuscated_incoming_pe_files': 0,
    'fast_clustered_files': 0,
    'fast_clustered_incoming_files': 0,
    'slow_clustered_files': 0,
    'slow_clustered_incoming_files': 0,
    'good_clusters': 0,
    'total_clustered_files': 0,
    'mean_cluster_size': 0,
    'successfully_clustered_incoming': 0,
    'not_clustered_incoming': 0,
    'share_successful': 0,
    'resource_clustered_files': 0
}                           # Dictionary to store statistics of the clustering

def analyse_files():
    for fileinfo in files.values():
        stats['total_pe_files'] += 1

        if fileinfo['fast_clustered']:
            stats['fast_clustered_files'] += 1
        if fileinfo['slow_clustered']:
            stats['slow_clustered_files'] += 1
        
        if fileinfo['incoming']:
            stats['incoming_pe'] += 1
            if fileinfo['unpacks_to_nonpacked_pe']:
                stats['successfully_unpacked_incoming'] += 1
            if fileinfo['obfuscation'] is not None:
                stats['obfuscated_incoming_pe_files'] += 1
            if fileinfo['fast_clustered']:
                stats['fast_clustered_incoming_files'] += 1
            if fileinfo['slow_clustered']:
                stats['slow_clustered_incoming_files'] += 1
        else:
            # If not incoming
            if fileinfo['obfuscation'] is not None:
                stats['obfuscated_unpacked_pe_files'] += 1


def analyse_clusters():
    # Analyse imphash clusters
    stats['imphash_mean_purity'], stats['imphash_mean_size'], stats['imphash_clustered_files'], stats['imphash_clusters'] = analyse_feature_clusters(clusters['imphash_clusters'])

    # Analyse icon clusters
    stats['icon_mean_purity'], stats['icon_mean_size'], stats['icon_clustered_files'], stats['icon_clusters'] = analyse_feature_clusters(clusters['icon_clusters'])

    # Analyse resource clusters
    stats['resource_mean_purity'], stats['resource_mean_size'], ignore, stats['resource_clusters'] = analyse_feature_clusters(clusters['resource_clusters'])

    # Analyse tlsh clusters
    stats['tlsh_mean_purity'], stats['tlsh_mean_size'], stats['tlsh_clustered_files'], stats['tlsh_clusters'] = analyse_feature_clusters(clusters['tlsh_clusters'])

def analyse_feature_clusters(clusters):
    number_of_clusters = 0
    total_files = 0
    mean_purity = 0
    mean_size = 0
    for cluster in clusters.values():
        cluster_purity, cluster_size, most_common_family, files_in_most_common = clustering.analyse_file_cluster(cluster['items'], files, True)
        if cluster_size:
            number_of_clusters += 1
            mean_purity += cluster_purity
            mean_size += cluster_size
            total_files += cluster_size
    if number_of_clusters != 0:
        mean_purity = mean_purity / number_of_clusters
        mean_size = mean_size / number_of_clusters
    else:
        mean_purity = 0
        mean_size = 0
    return mean_purity, mean_size, total_files, number_of_clusters


# Write results to pickles to allow further processing
if not os.path.exists('pickles/files.pkl') or not os.path.exists('pickles/clusters.pkl'):
    print("Pickles not found. Execute clustering first.")
    raise SystemExit

with open('pickles/files.pkl', 'rb') as picklefile:
    files = pickle.load(picklefile)
with open('pickles/clusters.pkl', 'rb') as picklefile:
    clusters = pickle.load(picklefile)

analyse_files()
analyse_clusters()

stats['unpacked_pe_files'] = stats['total_pe_files'] - stats['incoming_pe']
stats['total_obfuscated_pe_files'] = stats['obfuscated_incoming_pe_files'] + stats['obfuscated_unpacked_pe_files']

for key, value in stats.items():
    print(str(key) + ": " + str(value))
