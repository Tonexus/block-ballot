#!/bin/bash

nohup python3 run_issuer.py -p 12345
nohup python3 run_processor.py -p 30001 -c config.json -i 1