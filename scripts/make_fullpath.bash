#!/bin/bash

# Used to assist creating full paths for files. This is done by joining a base directory with given input.
# Input can either come from stdin or be contained in a file that is given as argument to this script.

# Base directory, the path that should be prepended to the lines in the input
base_dir="/some/path/to/data_set/"

while read line
do
    echo "$base_dir$line"
done < "${1:-/dev/stdin}"
