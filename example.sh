#!/bin/bash

python ec2_bench.py \
    --region us-west-2 \
    --vpc-id vpc-1234567 \
    --instance-type c7i.large c7gn.large c7gd.large c7g.large c7a.large c7i-flex.large

