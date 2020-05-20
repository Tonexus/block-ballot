import xmlrpc.client
from ballot import Ballot

config = {}
config['issuer_address'] = 'http://localhost:12345/ISSUER'
config['node_addresses'] = []
b = Ballot(config)
b.public = "my public address"
print(b.register())


i = xmlrpc.client.ServerProxy(config['issuer_address'])

print(i.list_registered_voters())