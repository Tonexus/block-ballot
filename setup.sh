#!/bin/bash
echo $1
for ((i = 0; i <= $1; i++ )); do
	echo "nohup python3 run_processor.py -c config.json -i $i  > ./logs/output$i.log &"
	nohup python3 run_processor.py -c config.json -i $i  > ./logs/output$i.log &
done
echo "nohup python3 run_issuer.py -c config.json > ./logs/outputIssuer.log &"
nohup python3 run_issuer.py -c config.json > ./logs/outputIssuer.log &
echo Setup done