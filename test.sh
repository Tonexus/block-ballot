#!/bin/bash

for INDEX in {0..2}
do
	nohup python3 run_processor.py -c config.json -i $INDEX  > ./output/output$INDEX.log &
done
sleep 5
nohup python3 run_issuer.py -p 12345 > ./output/outputIssuer.log &
sleep 5
echo Setup done