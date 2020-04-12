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

import feature_extraction
import clustering

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
    'learning_purity': 0,
    'items': set()
}
"""

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
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

def feature_extraction_worker():
    """
    Connect to feature extraction (job) queue and clustering (job done) queue
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
                # TODO: fiks TRAINING:
                TRAINING = True
                result = feature_extraction.analyse_file(file_to_cluster['path'], family=file_to_cluster['family'], incoming=True, training=TRAINING)
                send_to_done_queue(result, done_queue)

def send_to_done_queue(fileinfo, done_queue):
    """
    Recursively send files to the queue of completed feature extraction jobs
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
    TODO: Dokumenter
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
    TODO: Dokumenter
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

def collect_features():
    """
    TODO: Dokumenter
    """
    global files
    global clusters

    number_of_files = 0
    done_queue = get_done_queue()

    # Attempt to retrieve a file from the done queue
    fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Continue while it is possible to retrieve a file
    while fileinfo is not None:
        fileinfo['learning'] = True
        if fileinfo['incoming']:
            number_of_files += 1
            print("Processing incoming file number: " + str(number_of_files))
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
                current_file['unpacks_from'].add(fileinfo['unpacks_from'])
        else:
            # If file has not been received before, add data
            if PRINT_PROGRESS:
                print("Storing file " + fileinfo['sha256'])

            # Convert "unpacks_from" to a set
            unpacks_from = fileinfo['unpacks_from']
            fileinfo['unpacks_from'] = set()
            if unpacks_from is not None:
                fileinfo['unpacks_from'].add(unpacks_from)
            files[fileinfo['sha256']] = fileinfo
        
        # Attempt to retrieve next file and continue loop
        fileinfo = get_fileinfo_from_done_queue(done_queue)

def cluster_incoming():
    """
    TODO: Dokumenter
    """
    global files
    global clusters
    # TODO: Cluster litt som under training
    # Men pass på at 
    number_of_files = 0
    done_queue = get_done_queue()

    correctly_labelled = 0
    incorrectly_labelled = 0
    not_labelled = 0

    # Attempt to retrieve a file from the done queue
    fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Continue while it is possible to retrieve a file
    while fileinfo is not None:
        if fileinfo['incoming']:
            number_of_files += 1
            print("Clustering incoming file number: " + str(number_of_files))
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
                current_file['unpacks_from'].add(fileinfo['unpacks_from'])
        else:
            # If file has not been received before, add data
            if PRINT_PROGRESS:
                print("Storing file " + fileinfo['sha256'])
            # Convert "unpacks_from" to a set
            unpacks_from = fileinfo['unpacks_from']
            fileinfo['unpacks_from'] = set()
            if unpacks_from is not None:
                fileinfo['unpacks_from'].add(unpacks_from)
            
            files[fileinfo['sha256']] = fileinfo
            # TODO: Cluster the file, label it
            clustering.cluster_file(fileinfo, files, clusters)
            clustering.label_file(fileinfo, clusters)
            
        if fileinfo['incoming']:
            if fileinfo['given_label'] is not None:
                if fileinfo['family'] == fileinfo['given_label']:
                    correctly_labelled += 1
                else:
                    incorrectly_labelled += 1
            else:
                not_labelled += 1

            # TODO: Check if correct label and store results
        
        # Attempt to retrieve next file and continue loop
        fileinfo = get_fileinfo_from_done_queue(done_queue)
    print("Correctly labelled: " + str(correctly_labelled))
    print("Incorrectly labelled: " + str(incorrectly_labelled))
    print("Not labelled: " + str(not_labelled))
    print("Total files: " + str(number_of_files))
    # TODO: Hva med filer som kommer inn, men som ikke kan parses av pefile?
    # Disse bør telles som "not labelled" og telle med på "number_of_files"

def save_to_pickles():
    """
    Save data to pickles to allow later processing.
    """
    global files
    global clusters
    # Write results to pickles to allow further processing
    if not os.path.exists('pickles/'):
        os.mkdir('pickles')

    with open('pickles/files.pkl', 'wb') as picklefile:
        pickle.dump(files, picklefile)
    with open('pickles/clusters.pkl', 'wb') as picklefile:
        pickle.dump(clusters, picklefile)

def load_from_pickles():
    global files
    global clusters
    """
    Load data from pickles
    """

    if not os.path.exists('pickles/files.pkl') or not os.path.exists('pickles/clusters.pkl'):
        print("No pickles found. Perform learning before attempting to test.")
        raise SystemExit
    
    with open('pickles/files.pkl', 'rb') as picklefile:
        files = pickle.load(picklefile)
    with open('pickles/clusters.pkl', 'rb') as picklefile:
        clusters = pickle.load(picklefile)

# If main script (not another thread/process)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run feature extraction/clustering')
    parser.add_argument('-N', '--number-of-workers', help='Integer specifying the number of feature extraction threads')
    parser.add_argument('-L', '--learn-list', help='Path to a text file containing filepaths to files in learning/training set, where each line consists of <path> <family>. Path must not contain any spaces.')
    parser.add_argument('-T', '--test-list', help='Path to a text file containing filepaths to files in testing set, where each line consists of <path> <family>. Path must not contain any spaces.')
    args = parser.parse_args()

    # Identify number of workers
    number_of_workers = multiprocessing.cpu_count()
    if args.number_of_workers is not None:
        number_of_workers = int(args.number_of_workers)

    # Fill list with files that should be sent to analysis
    files_for_analysis = []
    filename = None
    work_type = None
    if args.learn_list is not None:
        work_type = 'learn'
        filename = args.learn_list
    if args.test_list is not None:
        work_type = 'test'
        filename = args.test_list

    if not filename:
        # Print help if no arguments were specified
        print("At least one of the following combinations must be supplied: -L <path to file> | -T <path to file>")
        parser.print_help()
    else:
        # Load paths and families from file and process the files
        with open(filename, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                path, fam = line.split(' ')
                files_for_analysis.append({'path': path, 'family': fam})

        if not files_for_analysis:
            print("No files to analyse")
        else:
            # If filepaths have been loaded
            # Create queue daemon for files to perform feature extraction on
            multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, JOB_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True).start()

            # Create queue daemon for files to perform clustering on 
            multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, DONE_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True).start()

            # Sleep for 0.2 second to ensure queues are running
            time.sleep(0.2)

            multiprocessing.Process(target=add_files_for_extraction, args=files_for_analysis, daemon=True).start()

            # Create a thread that retrieves files from feature extraction queue,
            # extracts their features and adds them to the clustering queue.
            for i in range(number_of_workers):
                multiprocessing.Process(target=feature_extraction_worker, daemon=True).start()

            if work_type == 'learn':
                collect_features()

                clustering.cluster_files(files, clusters)

                clustering.label_clusters(files, clusters)

                # TODO: Remove line (and outcommenting a few lines below):
                save_to_pickles()
            elif work_type == 'test':
                load_from_pickles()
                cluster_incoming()

                # TODO: Analyse clusters

            # TODO: Remove comment
            #save_to_pickles()

            print("Main done")
