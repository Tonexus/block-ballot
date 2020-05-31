from server import serve_processor
# Include standard modules
import argparse
import json
import re
# print("Hello World")
parser = argparse.ArgumentParser()
parser.add_argument("--port", "-p", help="set port to run the Issuer on")
parser.add_argument("--config", "-c", help="set config file")
parser.add_argument("--id", "-i", help="Set node_id")
args = parser.parse_args()

if args.config:
	print("Set config file to %s" % args.config)
else:
	exit()
with open(args.config, 'r') as f:
    config = json.load(f)

if args.id:
	print("Set the id to %s" % args.id)
elif args.port:
	print("Set the port to %s" % args.port)
else:
	exit()

port = 0
# Can just have a list of ports for all localhost
if 'nodes' not in config:
	# expect list of ports
	if 'node_ports' not in  config:
		exit()
	else:
		config['nodes'] = list(map(lambda x : 'http://localhost:' + str(x) + "/PROCESSOR", config['node_ports']))
		port = config['node_ports'][int(args.id)]
else:
	# can parse the port from the url list of nodes if list of urls given
	p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
	m = re.search(p,config['nodes'][int(args.id)])
	m.group('host') # 'www.abc.com'
	port = int(m.group('port')) # '123'


print("Port %s" % port)
print(config)
config['processor_config']['initblockchain'] = None
config['processor_config']['node_id'] = int(args.id)
config['processor_config']['issuer_id'] = None
config['processor_config']['node_addresses'] = config['nodes']
serve_processor(config['processor_config'], port)






