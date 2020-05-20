from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from ballot import Issuer

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/ISSUER',)


def serve_issuer(config, port):
	""" Makes a rpc server for issuers"""
	with SimpleXMLRPCServer(('localhost', port),
	                        requestHandler=RequestHandler) as server:
	    server.register_introspection_functions()
	    server.register_instance(Issuer(config))
	    server.serve_forever()

