#!/bin/bash

for split in {1..5};
do
    dataset="ijcnn"
    outfile="local/results/$dataset-$split.txt"
    picklepath="pickles/$dataset-k-fold_$split"

    echo "Feature extraction:" > "$outfile"
    { time ./run.py -E "local/$dataset-k-fold-splits/train_k-fold_$split.txt"; } &>> "$outfile"
    echo "Clustering:" >> "$outfile"
    { time ./run.py -C; } &>> "$outfile"
    echo "Validation:" >> "$outfile"
    { time ./run.py -V "local/$dataset-k-fold-splits/test_k-fold_$split.txt"; } &>> "$outfile"
    echo "Counting files in need of in-depth analysis:" >> "$outfile"
    { time ./count_files_requiring_analysis.py; } &>> "$outfile"
    mkdir -p "$picklepath"
    cp -r "pickles/extracted/" "$picklepath/extracted/"
    cp -r "pickles/clustered/" "$picklepath/clustered/"
    cp  -r "pickles/validated/" "$picklepath/validated/"
done
