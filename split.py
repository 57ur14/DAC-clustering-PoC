#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sklearn.model_selection import train_test_split

listfile = open('files.txt', 'r')
files = listfile.read().splitlines()
listfile.close()

train, test = train_test_split(files)

trainfilesfile = open('train.txt', 'w')
for tr in train:
    trainfilesfile.write(tr + '\n')
trainfilesfile.close()

testfilesfile = open('test.txt', 'w')
for te in test:
    testfilesfile.write(te + '\n')
testfilesfile.close()