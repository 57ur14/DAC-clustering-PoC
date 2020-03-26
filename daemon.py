#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import multiprocessing
import os
import pickle
import queue
import signal
from collections import Counter
from multiprocessing.managers import BaseManager

import clustering
import feature_extraction

# Retreive configuration
config = configparser.ConfigParser()
config.read('config.ini')
PRINT_PROGRESS = config.getboolean('clustering', 'print_progress')
START_OVER = config.getboolean('clustering', 'start_over')
QUEUE_MANAGER_IP = config.get('queue_managers', 'ip')
EXTRACTION_MANAGER_PORT = config.getint('queue_managers', 'extraction_port')
CLUSTER_MANAGER_PORT = config.getint('queue_managers', 'clustering_port')
QUEUE_MANAGER_KEY = config.get('queue_managers', 'key').encode('utf-8')
QUEUE_TIMEOUT = config.getint('queue_managers', 'timeout')
EXTRACTION_THREADS_COUNT = config.getint('queue_managers', 'extraction_threads_count')

# Define queue manager class
class QueueManager(BaseManager):
    pass
QueueManager.register('get_queue')

def sigint_handler(signum, frame):
    """
    Do not quit immediately if recieving SIGINT.
    In stead, modify "continue_working" such that the script 
    will stop attempting to retrieve new items from the queue
    and rather save variables to pickles.
    """
    print("SIGINT recieved. Quitting and saving state after processing the current file.")
    global continue_working
    continue_working = False

def perform_clustering():
    if START_OVER == False:
        clustering.load_from_pickles()

    # Connect to queue
    cluster_manager = QueueManager(address=(QUEUE_MANAGER_IP, CLUSTER_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        cluster_manager.connect()
    except:
        print("Cannot connect to queue manager. Please check the configuration.")
        raise SystemExit
    cluster_queue = cluster_manager.get_queue()

    # Start working on elements in queue
    global continue_working
    while continue_working == True:
        try:
            file_to_cluster = cluster_queue.get(timeout=QUEUE_TIMEOUT)
        except EOFError:
            print("Queue not available. Please check if the queue manager is still running.")
            break
        except queue.Empty:
            # Stop if queue is empty and SIGINT has been sent
            if continue_working == True:
                print("Waiting for files to cluster")
                continue
            else:
                break
        else:
            if file_to_cluster['sha256'] in clustering.files.keys():
                if PRINT_PROGRESS == True:
                    print("Merging file with existing information  " + file_to_cluster['sha256'])
                # If file has been received and clustered before
                # Merge new data into the existing data.
                current_file = clustering.files[file_to_cluster['sha256']]
                if file_to_cluster['incoming']:
                    current_file['incoming'] = True
                else:       # If file is not incoming (was unpacked from another file)
                    if current_file['incoming']:
                        current_file['incoming'] = True
                    # Update "unpacks_from" since it might be contained in multiple different binaries
                    current_file['unpacks_from'].update(file_to_cluster['unpacks_from'])
            else:
                if PRINT_PROGRESS == True:
                    print("Clustering file " + file_to_cluster['sha256'])
                clustering.files[file_to_cluster['sha256']] = file_to_cluster
                clustering.cluster_file(file_to_cluster)   
            # TODO: Write to file?

    # Save results to pickles when done working
    clustering.save_to_pickles()

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

def add_files_for_extraction(*file_list):
    """
    Add files to the queue of files that should have their 
    features extracted and their data sent to clustering
    """

    # Connect to feature extraction queue
    extraction_manager = QueueManager(address=(QUEUE_MANAGER_IP, EXTRACTION_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        extraction_manager.connect()
    except:
        print("Cannot connect to queue manager. Please check the configuration.")
    else:
        extraction_queue = extraction_manager.get_queue()
        for item in file_list:
            # Send all files in the list to the feature extraction queue
            extraction_queue.put(item)

def feature_extraction_worker():
    # Connect to feature extraction queue
    extraction_manager = QueueManager(address=(QUEUE_MANAGER_IP, EXTRACTION_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    cluster_manager = QueueManager(address=(QUEUE_MANAGER_IP, CLUSTER_MANAGER_PORT), authkey=QUEUE_MANAGER_KEY)
    try:
        extraction_manager.connect()
        cluster_manager.connect()
    except:
        print("Cannot connect to queue manager. Please check the configuration.")
    else:
        extraction_queue = extraction_manager.get_queue()
        cluster_queue = cluster_manager.get_queue()

        global continue_working
        while continue_working == True:
            try:
                file_to_cluster = extraction_queue.get(timeout=QUEUE_TIMEOUT)
            except EOFError:
                print("Queue not available. Please check if the feature extraction queue manager is still running.")
                break
            except queue.Empty:
                # Stop if queue is empty and SIGINT has been sent
                if continue_working == True:
                    print("Waiting for files to extract")
                    continue
                else:
                    break
            else:
                result = feature_extraction.analyse_file(file_to_cluster['path'], family=file_to_cluster['family'], incoming=True)
                send_to_clustering(result, cluster_queue)

def send_to_clustering(fileinfo, cluster_queue):
    """
    Recursively send files to the clustering queue.
    Send contained files first since the parents can be clustered
    based on the properties of their children.
    """
    for value in fileinfo['contained_pe_fileinfo'].values():
        send_to_clustering(value, cluster_queue)
    fileinfo.pop('contained_pe_fileinfo')
    cluster_queue.put(fileinfo)

# If main script (not another thread/process)
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Process a file; Extract features and send to clustering.')
    parser.add_argument('-P', '--path', help='Path to a single file that should be processed.')
    parser.add_argument('-F', '--family', help='Malware family the single file belongs to (optional)')
    parser.add_argument('-L', '--list', help='Path to a file containing paths to files on separate lines')
    parser.add_argument('-C', '--combined-list', help='Path to a file where each line consists of <path> <family>. Path must not contain any spaces.')
    args = parser.parse_args()
    
    # Fill list with files that should be sent to analysis
    files_for_analysis = []
    if args.path is not None:
        # Process single specified file
        files_for_analysis.append({'path': args.path, 'family': args.family})
    elif args.list is not None:
        # Load paths from file and process files
        with open(args.list, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                files_for_analysis.append({'path': line, 'family': None})
    elif args.combined_list is not None:
        # Load paths and families from file and process the files
        with open(args.combined_list, 'r') as infile:
            lines = infile.read().splitlines()
            for line in lines:
                path, fam = line.split(' ')
                files_for_analysis.append({'path': path, 'family': fam})
    else:
        # Print help if no arguments were specified
        print("At least one of the following combinations must be supplied: (-P <path> [-F <family>]) | -L <path to list> | -C <path to combined-list>")
        parser.print_help()

    # Quit if no files to analysis
    if not files_for_analysis:
        print("No files to analyse")
    else:
        continue_working = True
        # Create SIGINT handler to avoid shutting down while clustering
        signal.signal(signal.SIGINT, sigint_handler)

        # Create queue daemon for files to perform feature extraction on
        feat_ext_queue_proc = multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, EXTRACTION_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True)
        feat_ext_queue_proc.start()

        # Create queue daemon for files to perform clustering on 
        cluster_queue_proc = multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, CLUSTER_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True)
        cluster_queue_proc.start()

        # Create a thread that adds files to feature extraction queue
        add_files_proc = multiprocessing.Process(target=add_files_for_extraction, args=files_for_analysis)
        add_files_proc.start()

        # Create a thread that retrieves files from feature extraction queue,
        # extracts their features and adds them to the clustering queue.
        feature_extraction_processes = []
        for i in range(EXTRACTION_THREADS_COUNT):
            p = multiprocessing.Process(target=feature_extraction_worker, daemon=True)
            p.start()
            feature_extraction_processes.append(p)

        # Create a process that performs clustering on items in the clustering queue
        clustering_proc = multiprocessing.Process(target=perform_clustering)
        clustering_proc.start()
        
        # Wait until threads have finished
        add_files_proc.join()
        for proc in feature_extraction_processes:
            # Wait until all feature extraction processes have quit
            proc.join()
        clustering_proc.join()
        print("Done")
