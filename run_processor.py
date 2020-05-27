from server import serve_processor
# Include standard modules
import argparse
import json
# print("Hello World")
parser = argparse.ArgumentParser()
parser.add_argument("--port", "-p", help="set port to run the Issuer on")
parser.add_argument("--config", "-c", help="set config file")
parser.add_argument("--id", "-i", help="Set node_id")
args = parser.parse_args()

if args.port:
    print("Set port to %s" % args.port)
else:
	exit()

if args.config:
	print("Set config file to %s" % args.config)
else:
	exit()
with open(args.config, 'r') as f:
    config = json.load(f)

print(config)
config['processor_config']['initblockchain'] = None
config['processor_config']['node_id'] = int(args.id)
config['processor_config']['issuer_id'] = None
serve_processor(config['processor_config'], int(args.port))






