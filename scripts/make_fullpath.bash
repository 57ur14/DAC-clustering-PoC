#!/bin/bash

base_dir="/home/sturla/IJCNN_10000files/"

while read line
do
    echo "$base_dir$line"
done < "${1:-/dev/stdin}"
