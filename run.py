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
    'label': '',
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
    # Connect to feature extraction queue and clustering queue
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

def collect_features():

    # Connect to queue
    done_manager = QueueManager(address=(QUEUE_MANAGER_IP, DONE_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        done_manager.connect()
    except:
        print("Cannot connect to queue manager. Please try again or check the configuration.")
        raise SystemExit
    done_queue = done_manager.get_queue()

    while True:
        try:
            # Retrieve file metadata from queue
            fileinfo = done_queue.get(timeout=QUEUE_TIMEOUT)
        except EOFError:
            print("Queue not available. Please check if the queue manager is still running.")
            break
        except queue.Empty:
            print("Done queue empty. Stopping collection.")
            break
        else:
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

def cluster_incoming():
    pass

def save_to_pickles(work_type):
    """
    Save data to pickles to allow later processing.
    Saves the "files" variable to disk.
    If work_type is 'test', the "clusters" variable will be saved as well.
    """

    # Write results to pickles to allow further processing
    if not os.path.exists('pickles/'):
        os.mkdir('pickles')

    with open('pickles/files.pkl', 'wb') as picklefile:
        pickle.dump(files, picklefile)

    if work_type == 'test':
        with open('pickles/clusters.pkl', 'wb') as picklefile:
            pickle.dump(clusters, picklefile)

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

                # TODO: Analyse and label clusters

                # Save results to pickles when done working
                save_to_pickles(work_type)
            elif work_type == 'test':
                # TODO: Load file / cluster information

                cluster_incoming()

                # TODO: Analyse clusters

                save_to_pickles(work_type)

            print("Main done")
