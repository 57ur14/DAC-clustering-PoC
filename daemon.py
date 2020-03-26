#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import multiprocessing
import queue
import signal
import time
from multiprocessing.managers import BaseManager

import clustering

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
        print("Cannot connect to queue manager. Please try again or check the configuration.")
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

# If main script (not another thread/process)
if __name__ == '__main__':
    continue_working = True
    # Create SIGINT handler to avoid shutting down while clustering
    signal.signal(signal.SIGINT, sigint_handler)

    # Create queue daemon for files to perform feature extraction on
    feat_ext_queue_proc = multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, EXTRACTION_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True)
    feat_ext_queue_proc.start()

    # Create queue daemon for files to perform clustering on 
    cluster_queue_proc = multiprocessing.Process(target=serve_simple_queue, args=(QUEUE_MANAGER_IP, CLUSTER_MANAGER_PORT, QUEUE_MANAGER_KEY), daemon=True)
    cluster_queue_proc.start()

    # Sleep for a second to ensure queues are running
    time.sleep(1)

    # Create a process that performs clustering on items in the clustering queue
    clustering_proc = multiprocessing.Process(target=perform_clustering)
    clustering_proc.start()

    clustering_proc.join()
    print("Daemon stopped")
