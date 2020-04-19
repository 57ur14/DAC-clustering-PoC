#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sklearn.model_selection import KFold
import argparse
import os

parser = argparse.ArgumentParser(description='Split a file into multiple train and test files for K-fold cross-validation.')
parser.add_argument('filepath', help='Path to a file that should be split into train and test sets.')
parser.add_argument('-K', type=int, default=5, help='Number of groups the data set should be split into (default = 5)')
args = parser.parse_args()

files_for_analysis = []
with open(args.filepath, 'r') as infile:
    lines = infile.read().splitlines()
    for line in lines:
        path, fam = line.split(' ')
        files_for_analysis.append({'path': path, 'family': fam})
    number_of_files = len(files_for_analysis)

if files_for_analysis:
    kf = KFold(n_splits=args.K)
    split_number = 1

    if not os.path.exists('k-fold-splits/'):
        os.makedirs('k-fold-splits/')

    for train, test in kf.split(files_for_analysis):
        train_filename = 'k-fold-splits/train_k-fold_' + str(split_number) + '.txt'
        test_filename = 'k-fold-splits/test_k-fold_' + str(split_number) + '.txt'
        with open(train_filename, 'w') as train_file:
            for train_index in train:
                line = files_for_analysis[train_index]
                train_file.write(line['path'] + ' ' + line['family'] + '\n')
        with open(test_filename, 'w') as test_file:
            for test_index in test:
                line = files_for_analysis[test_index]
                test_file.write(line['path'] + ' ' + line['family'] + '\n')
        split_number += 1