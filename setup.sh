#!/bin/bash
echo $1
for ((i = 0; i <= $1; i++ )); do
	echo "nohup python3 run_processor.py -c config.json -i $i  > ./logs/output$i.log &"
	echo -e "\n\nA new run of this processor\n\n" >> ./logs/output$i.log
	echo -e "\n\nA new run of the processor\n\n" >> ./logs/processor_$i.log
	nohup python3 run_processor.py -c config.json -i $i  > ./logs/output$i.log &
done
echo -e "\n\nA new run of the issuer\n\n" >> ./logs/outputIssuer.log
echo -e "\n\nA new run of the issuer\n\n" >> ./logs/processor.log
echo "nohup python3 run_issuer.py -c config.json > ./logs/outputIssuer.log &"
nohup python3 run_issuer.py -c config.json > ./logs/outputIssuer.log &
echo Setup done