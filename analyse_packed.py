#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import multiprocessing
import os
import queue
import time
from multiprocessing.managers import BaseManager

import unpacking

# Data structure for storing files
files = {}

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

def feature_extraction_worker():
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
                result = {
                    'unpacking_result': unpacking.detect_obfuscation_by_diec(file_to_cluster['path']),
                    'family': file_to_cluster['family']
                }
                done_queue.put(result)

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
        if PRINT_PROGRESS:
            print("Done-queue empty. Stopping collection.")
        return None

def collect_features(files):
    """
    Retrieve fileinfo/file feature dictionaries from the
    feature extraction workers and store the feature
    information in the global "files" data structure.
    """

    done_queue = get_done_queue()
    families = {}

    # Attempt to retrieve a file from the done queue
    fileinfo = get_fileinfo_from_done_queue(done_queue)
    # Continue while it is possible to retrieve a file
    while fileinfo is not None:
        if fileinfo['family'] not in families.keys():
            families[fileinfo['family']] = {
                'packed': 0,
                'non-packed': 0,
                'total': 0
            }
        
        families[fileinfo['family']]['total'] += 1

        if fileinfo['unpacking_result'] is not None:
            print(fileinfo['family'] + ": Packed")
            families[fileinfo['family']]['packed'] += 1
        else:
            print(fileinfo['family'] + ": Non-packed")
            families[fileinfo['family']]['non-packed'] += 1

        # Attempt to retrieve next file and continue loop
        fileinfo = get_fileinfo_from_done_queue(done_queue)
    return families

# If main script (not another thread/process)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run feature extraction/clustering')
    parser.add_argument('-N', '--number-of-workers', type=int, default=multiprocessing.cpu_count(), help='Integer specifying the number of feature extraction threads')
    parser.add_argument('filepath', help='Path to a text file containing filepaths to files that should have their features extracted (for clustering), where each line consists of <path> <family>. Path must not contain any spaces.')
    args = parser.parse_args()

    # Fill list with files that should be sent to analysis
    files_for_analysis = []
    filename = None
    do_analysis = False
    if args.filepath is not None:
        filename = args.filepath
        do_analysis = True
    
    if do_analysis:
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
            multiprocessing.Process(target=feature_extraction_worker, daemon=True).start()

        result = collect_features(files)

        for key, value in result.items():
            print(str(key) + ": " + str(value))