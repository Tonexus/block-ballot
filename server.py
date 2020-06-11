from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from ballot import Issuer
from process import ProcessNode
import socketserver

# Restrict to a particular path.
# class RequestHandlerIssuer(SimpleXMLRPCRequestHandler):

class RequestHandlerIssuer(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/ISSUER',)
    def _dispatch(self, method, params):
        try:
            # print(self.server.funcs)
            # print(dir(self.server.instance))
            method_to_call = getattr(self.server.instance, method)
            return method_to_call(*params)
        except:
            import traceback
            traceback.print_exc()
            raise


def serve_issuer(config, port):
    """ Makes a rpc server for issuers"""
    with SimpleXMLRPCServer(('localhost', port),
                            requestHandler=RequestHandlerIssuer, allow_none=True) as server:
        server.register_introspection_functions()
        server.register_instance(Issuer(config))
        server.serve_forever()

# Restrict to a particular path.
# class RequestHandlerProcessor(SimpleXMLRPCRequestHandler):
    # rpc_paths = ('/PROCESSOR',)

class RPCThreading(socketserver.ThreadingMixIn, SimpleXMLRPCServer):
    pass

class RequestHandlerProcessor(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/PROCESSOR',)
    def _dispatch(self, method, params):
        try: 
            method_to_call = getattr(self.server.instance, method)
            return method_to_call(*params)
        except:
            import traceback
            File_object = open(r"logs/processor_"+str(self.server.instance.id)+".log", "a")
            traceback.print_exc(file=File_object)
            raise


def serve_processor(config, port):
    """ Makes a rpc server for issuers"""
    with RPCThreading(('localhost', port),
                            requestHandler=RequestHandlerProcessor, allow_none=True) as server:
        server.register_introspection_functions()
        server.register_instance(ProcessNode(**config))
        server.serve_forever()

