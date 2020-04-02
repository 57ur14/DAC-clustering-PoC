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

def cluster_files(files, clusters):
    """
    Create clusters based on file features
    """
    pass

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
