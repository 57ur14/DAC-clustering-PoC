#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import multiprocessing
import os
import pickle
import queue
import time
from multiprocessing.managers import BaseManager

import clustering
import feature_extraction

# Data structure for storing files
files = {}
clusters = {
    'imphash_clusters': {},
    'icon_clusters': {},
    'resource_clusters': {},
    'tlsh_clusters': {}
}

"""
Innhold i hver cluster:
dict_name[key] = {
    'label': None,
    'training_purity': 0,
    'items': set()
}
"""

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('general', 'print_progress')
QUEUE_MANAGER_IP = config.get('queue_managers', 'ip')
JOB_MANAGER_PORT = config.getint('queue_managers', 'job_port')
DONE_MANAGER_PORT = config.getint('queue_managers', 'done_port')
QUEUE_MANAGER_KEY = config.get('queue_managers', 'key').encode('utf-8')
QUEUE_TIMEOUT = config.getint('queue_managers', 'timeout')

# Define queue manager class
class QueueManager(BaseManager):
    pass
QueueManager.register('get_queue')

def serve_simple_queue(ip, port, key):
    """
    Start a queue on the specified port
    Start as new thread/process as the function will run "serve_forever()".
    """
    simple_queue = queue.Queue()
    QueueManager.register('get_queue', callable=lambda:simple_queue)
    manager = QueueManager(address=(ip, port), authkey=key)
    server = manager.get_server()
    server.serve_forever()

def feature_extraction_worker(training=False):
    """
    Connect to feature extraction (job) queue and clustering (job done) queue
    If training is True, the file will be marked as being part of the training data set.
    """
    job_manager = QueueManager(address=(QUEUE_MANAGER_IP, JOB_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    done_manager = QueueManager(address=(QUEUE_MANAGER_IP, DONE_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        job_manager.connect()
        done_manager.connect()
    except:
        print("Cannot connect to queue manager. Please check the configuration.")
    else:
        job_queue = job_manager.get_queue()
        done_queue = done_manager.get_queue()

        while True:
            try:
                file_to_cluster = job_queue.get(timeout=QUEUE_TIMEOUT)
            except EOFError:
                print("Queue not available. Please check if the feature extraction queue manager is still running.")
                break
            except queue.Empty:
                # Stop when queue is empty
                break
            else:
                result = feature_extraction.analyse_file(file_to_cluster['path'], family=file_to_cluster['family'], incoming=True, training=training)
                send_to_done_queue(result, done_queue)

def send_to_done_queue(fileinfo, done_queue):
    """
    Recursively send files to the queue of
    completed feature extraction jobs
    """
    if fileinfo is not None:
        for contained_info in fileinfo['contained_pe_fileinfo'].values():
            send_to_done_queue(contained_info, done_queue)
        fileinfo.pop('contained_pe_fileinfo')
        done_queue.put(fileinfo)

def add_files_for_extraction(*file_list):
    """
    Add files to the queue of files that should have their 
    features extracted and their data sent to clustering
    """
    job_manager = QueueManager(address=(QUEUE_MANAGER_IP, JOB_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:        # Connect to feature extraction queue
        job_manager.connect()
    except:
        print("Cannot connect to queue manager. Make sure the daemon is running and the configuration is correct.")
    else:
        job_queue = job_manager.get_queue()
        for item in file_list:
            # Send all files in the list to the feature extraction queue
            job_queue.put(item)

def get_done_queue():
    """
    Retrieve a queue object from a queue manager created
    with the options provided in the config file.
    """
    done_manager = QueueManager(address=(QUEUE_MANAGER_IP, DONE_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        done_manager.connect()
    except:
        print("Cannot connect to queue manager. Please try again or check the configuration.")
        raise SystemExit
    return done_manager.get_queue()

def get_fileinfo_from_done_queue(done_queue):
    """
    Returns one fileinfo/file feature dictionary from
    the provided queue object.
    """
    try:
        # Return file metadata the done queue
        return done_queue.get(timeout=QUEUE_TIMEOUT)
    except EOFError:
        print("Queue not available. Please check if the queue manager is still running.")
        return None
    except queue.Empty:
        print("Done-queue empty. Stopping collection.")
        return None

def collect_features(files):
    """
    Retrieve fileinfo/file feature dictionaries from the
    feature extraction workers and store the feature
    information in the global "files" data structure.
    """

    incoming_files_parsed = 0
    done_queue = get_done_queue()

    # Attempt to retrieve a file from the done queue
    fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Continue while it is possible to retrieve a file
    while fileinfo is not None:
        fileinfo['training'] = True
        if fileinfo['incoming']:
            incoming_files_parsed += 1
            print("Processing incoming file number: " + str(incoming_files_parsed))
        # If file was successfully retrieved from queue
        if fileinfo['sha256'] in files.keys():
            # If file has been received and clustered before
            # Merge new data into the existing data.
            if PRINT_PROGRESS:
                print("Merging file with existing information  " + fileinfo['sha256'])
            current_file = files[fileinfo['sha256']]
            if fileinfo['incoming']:
                current_file['incoming'] = True
            else:       # If file is not incoming (was unpacked from another file)
                # Update "unpacks_from" since it might be contained in multiple different binaries
                current_file['unpacks_from'].update(fileinfo['unpacks_from'])
        else:
            # If file has not been received before, add data
            if PRINT_PROGRESS:
                print("Storing file " + fileinfo['sha256'])
            # Add file information to global data structure
            files[fileinfo['sha256']] = fileinfo
        
        # Attempt to retrieve next file and continue loop
        fileinfo = get_fileinfo_from_done_queue(done_queue)

def cluster_and_validate_incoming(files, clusters):
    """
    Cluster and perform validation on files that are in the
    feature extraction job done queue.
    """
    done_queue = get_done_queue()
    
    incoming_files_parsed = 0
    correctly_labelled = 0
    incorrectly_labelled = 0
    not_labelled = 0
    labelled_packed = 0
    not_labelled_packed = 0
    fast_clustered = 0
    fast_clustered_incoming = 0
    slow_clustered = 0
    slow_clustered_incoming = 0

    # Attempt to retrieve a file from the done queue
    fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Continue while it is possible to retrieve a file
    while fileinfo is not None:
        if fileinfo['incoming']:
            incoming_files_parsed += 1
            print("Clustering incoming file number: " + str(incoming_files_parsed))
        # If file was successfully retrieved from queue
        if fileinfo['sha256'] in files.keys():
            # If file has been received and clustered before
            # Merge new data into the existing data.
            if PRINT_PROGRESS:
                print("Merging file with existing information  " + fileinfo['sha256'])
            current_file = files[fileinfo['sha256']]
            if fileinfo['incoming']:
                current_file['incoming'] = True
            else:       # If file is not incoming (was unpacked from another file)
                # Update "unpacks_from" since it might be contained in multiple different binaries
                current_file['unpacks_from'].update(fileinfo['unpacks_from'])
            if fileinfo['training']:
                # If file was introduced during training, label file
                fileinfo['given_label'] = fileinfo['family']
        else:
            # If file has not been received before, add data
            if PRINT_PROGRESS:
                print("Storing file " + fileinfo['sha256'])
            # Add file to global data structure            
            files[fileinfo['sha256']] = fileinfo

            # Cluster the file
            if clustering.cluster_file(fileinfo, files, clusters):
                fast_clustered += 1
                if fileinfo['incoming']:
                    fast_clustered_incoming += 1
            else:
                slow_clustered += 1
                if fileinfo['incoming']:
                    slow_clustered_incoming += 1
            # Label the file
            clustering.label_file(fileinfo, files, clusters)
            
        if fileinfo['incoming']:
            # Check if correctly labelled and store results
            if fileinfo['given_label'] is not None:
                if fileinfo['family'] == fileinfo['given_label']:
                    correctly_labelled += 1
                else:
                    incorrectly_labelled += 1
                if fileinfo['obfuscation']:
                    labelled_packed += 1
            else:
                not_labelled += 1
                if fileinfo['obfuscation'] is not None:
                    not_labelled_packed += 1
        
        # Attempt to retrieve next file and continue loop
        fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Return statistics:
    return {
        'correctly_labelled': correctly_labelled,
        'incorrectly_labelled': incorrectly_labelled,
        'not_labelled': not_labelled,
        'not_labelled_packed': not_labelled_packed,
        'labelled_packed': labelled_packed,
        'incoming_files_parsed': incoming_files_parsed,
        'fast_clustered': fast_clustered,
        'fast_clustered_incoming': fast_clustered_incoming,
        'slow_clustered': slow_clustered,
        'slow_clustered_incoming': slow_clustered_incoming
    }

def save_to_pickles(folder):
    """
    Save data to pickles to allow later processing.
    Folder should be the path to a folder where the 
    files "files.pkl" and "clusters.pkl" will be stored.
    Suggested values for folder:
        pickles/extracted/
        pickles/clustered/
        pickles/validated/
    """
    global files
    global clusters

    if not os.path.exists(folder):
        os.mkdir(folder)

    files_path = os.path.join(folder, 'files.pkl')
    clusters_path = os.path.join(folder, 'clusters.pkl')

    with open(files_path, 'wb') as picklefile:
        pickle.dump(files, picklefile)
    with open(clusters_path, 'wb') as picklefile:
        pickle.dump(clusters, picklefile)

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

# If main script (not another thread/process)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run feature extraction/clustering')
    parser.add_argument('-N', '--number-of-workers', type=int, default=multiprocessing.cpu_count(), help='Integer specifying the number of feature extraction threads')
    parser.add_argument('-E', '--extraction-list', help='Path to a text file containing filepaths to files that should have their features extracted (for clustering), where each line consists of <path> <family>. Path must not contain any spaces.')
    parser.add_argument('-C', '--cluster', action='store_true', help='Do clustering on files where features have been extracted.')
    parser.add_argument('-T', '--train-list', help='Equivalent of -E <filename> -C. Path to a text file containing filepaths to files in training set, where each line consists of <path> <family>. Path must not contain any spaces.')
    parser.add_argument('-V', '--validation-list', help='Path to a text file containing filepaths to files in validation set, where each line consists of <path> <family>. Path must not contain any spaces.')
    args = parser.parse_args()

    # Fill list with files that should be sent to analysis
    files_for_analysis = []
    filename = None
    mark_as_training = False
    do_extraction = False
    do_clustering = args.cluster
    do_validation = False
    if args.train_list is not None:
        filename = args.train_list
        mark_as_training = True
        do_extraction = True
        do_clustering = True
    if args.extraction_list is not None:
        filename = args.extraction_list
        mark_as_training = True
        do_extraction = True
    if args.validation_list is not None:
        filename = args.validation_list
        do_validation = True
    
    if do_extraction or do_validation:
        # Load paths and families from file and process the files
        with open(filename, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                path, fam = line.split(' ')
                files_for_analysis.append({'path': path, 'family': fam})
            number_of_files = len(files_for_analysis)

        if not number_of_files:
            print("No files to analyse")
            raise SystemExit

        # If filepaths have been loaded
        # Create queue daemon for files to perform feature extraction on
        multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, JOB_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True).start()

        # Create queue daemon for files to perform clustering on 
        multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, DONE_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True).start()

        # Sleep for 0.2 second to ensure queues are running
        time.sleep(0.2)

        multiprocessing.Process(target=add_files_for_extraction, args=(files_for_analysis), daemon=True).start()

        # Create a thread that retrieves files from feature extraction queue,
        # extracts their features and adds them to the clustering queue.
        for i in range(args.number_of_workers):
            multiprocessing.Process(target=feature_extraction_worker, args=(mark_as_training,), daemon=True).start()

    if do_extraction:
        # Store files coming from feature extraction job done queue.
        collect_features(files)
        # Save file features to pickles
        save_to_pickles('pickles/extracted/')
    if do_clustering:
        # Load file features from pickles
        if do_extraction or load_from_pickles('pickles/extracted/'):
            # Cluster the files based on extracted features
            clustering.cluster_files(files, clusters)
            # Label the created clusters
            clustering.label_clusters(files, clusters)

            clustering_statistics = clustering.analyse_clustered_files(files)
            clustering_statistics.update(clustering.analyse_clusters(files, clusters))
            for key, val in clustering_statistics.items():
                print(str(key) + ": " + str(val))

            # Save updated file information and clusters to pickles.
            save_to_pickles('pickles/clustered/')
    if do_validation:
        # Load files and clusters from training
        if load_from_pickles('pickles/clustered/', True):
            # Perform feature extraction, cluster and label 
            # files coming from feature extraction job done queue.
            validation_statistics = cluster_and_validate_incoming(files, clusters)

            # Calculate number of files not parsed
            validation_statistics['non_parsed_files'] = number_of_files - validation_statistics['incoming_files_parsed']
            
            # Print statistics when done:
            for key, val in validation_statistics.items():
                print(str(key) + ": " + str(val))
            
            # Save updated file information and clusters to pickles
            save_to_pickles('pickles/validated/')