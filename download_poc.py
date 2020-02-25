#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import mysql.connector as mariadb
import binascii

config = configparser.ConfigParser()
config.read('config.ini')

mariadb_connection = mariadb.connect(host=config['database']['host'], user=config['database']['user'], password=config['database']['password'], database=config['database']['database'])
cursor = mariadb_connection.cursor(dictionary=True)

print("Connected to database.")

cursor.execute('SELECT * FROM file WHERE training = 1 ORDER BY sha256 LIMIT 1000')

rows = cursor.fetchmany(10)

files = list()

while len(rows):
    for row in rows:
        fileinfo = {}
        fileinfo['sha256'] = binascii.hexlify(row['sha256']).decode('utf-8')
        fileinfo['md5'] = binascii.hexlify(row['md5']).decode('utf-8')
        fileinfo['file'] = row['file']
        fileinfo['family'] = row['family']
        files.append(fileinfo)
    rows = cursor.fetchmany(10)

for fileinfo in files:
    print(fileinfo['sha256'])