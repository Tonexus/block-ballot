from server import serve_issuer
import argparse
import json
import re

parser = argparse.ArgumentParser()
# parser.add_argument("--port", "-p", help="set port to run the Issuer on")
parser.add_argument("--config", "-c", help="set config file")
args = parser.parse_args()

# if args.port:
#     print("Set port to %s" % args.port)
# else:
# 	exit()


if args.config:
	print("Set config file to %s" % args.config)
else:
	print('Exiting due to no config file provided')
	exit()
with open(args.config, 'r') as f:
    config = json.load(f)

# Can just have a list of ports for all localhost
if 'nodes' not in config:
	# expect list of ports
	if 'node_ports' not in  config:
		exit()
	else:
		config['issuer_config']['node_addresses'] = list(map(lambda x : 'http://localhost:' + str(x) + "/PROCESSOR", config['node_ports']))
else:
	config['issuer_config']['node_addresses'] = config['nodes']

if 'processor_config' in config:
	if 'config' in config['processor_config']:
		p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
		m = re.search(p,config['processor_config']['config']['issuer_address'])
		m.group('host') # 'www.abc.com'
		port = int(m.group('port')) # '123'
		print('The port from the config file is ', port)
	else:
		print('Config file malformed')
		exit()
else:
	print('Config file malformed')
	exit()
	
serve_issuer(config['issuer_config'], int(port))





