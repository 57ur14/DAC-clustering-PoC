#!/bin/bash

while read  line
do
    family=$(echo "$line" | cut -d / -f 5) # Extract family from path in data set
    echo $line $family                     # Print with correct format
done < "${1:-/dev/stdin}"
