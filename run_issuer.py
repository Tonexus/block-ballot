from server import serve_issuer
# Include standard modules
import argparse
# print("Hello World")
parser = argparse.ArgumentParser()
parser.add_argument("--port", "-p", help="set port to run the Issuer on")
args = parser.parse_args()

if args.port:
    print("Set port to %s" % args.port)
else:
	exit()


config = {}
config['node_addresses'] = []
config['pow_config'] = 'pow config'
serve_issuer(config, int(args.port))





