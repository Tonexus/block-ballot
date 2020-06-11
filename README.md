To start the Issuer

python3 run_issuer.py -c <config file>

To run a processor

python3 run_processor.py -c <config file> -i <index into list of nodes in config file>

Config file json

{
	"issuer_config": {"num_zeros": 2, "transactions_per_block": 3},
	"processor_config": {
		"initblockchain" : "None",
		"voters_map" : {}, 
		"config": {
			"issuer_address": "https://localhost:12345/ISSUER"
		}
	},
	"nodes": ["http://localhost:30001/PROCESSOR"],
	"node_ports": [30001]

}

issuer_config - dict sent to the issuer on start up. Currently number of zeros for POW and transactions per block.
processor_config - contains the issuer address and an initblockchain. Currently will not change
Can have either of the below
nodes - list of nodes used if node_ports not set
node_ports - list of ports for the processors to be listening to to generate nodes list all on localhost

Above is all used in the script setup.sh along with run_issuer.py and run_processor.py files

To kill all the processes locally use ./kill.sh

All Errors and regular print output go to their files in logs. It is just a running total.