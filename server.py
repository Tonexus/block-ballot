from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from ballot import Issuer
from process import ProcessNode

# Restrict to a particular path.
class RequestHandlerIssuer(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/ISSUER',)


def serve_issuer(config, port):
	""" Makes a rpc server for issuers"""
	with SimpleXMLRPCServer(('localhost', port),
	                        requestHandler=RequestHandlerIssuer, allow_none=True) as server:
	    server.register_introspection_functions()
	    server.register_instance(Issuer(config))
	    server.serve_forever()

# Restrict to a particular path.
class RequestHandlerProcessor(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/PROCESSOR',)


def serve_processor(config, port):
	""" Makes a rpc server for issuers"""
	with SimpleXMLRPCServer(('localhost', port),
	                        requestHandler=RequestHandlerProcessor, allow_none=True) as server:
	    server.register_introspection_functions()
	    server.register_instance(ProcessNode(**config))
	    server.serve_forever()

