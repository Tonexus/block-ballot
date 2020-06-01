import xmlrpc.client
from ballot import Ballot



config = {}
config['issuer_address'] = 'http://localhost:12345/ISSUER'
# config['node_addresses'] = ["http://localhost:30001/PROCESSOR", "http://localhost:30002/PROCESSOR", "http://localhost:30003/PROCESSOR"]
config['node_addresses'] = ["http://localhost:30001/PROCESSOR"]


i = xmlrpc.client.ServerProxy(config['issuer_address'])

print(i.start_election())

b = Ballot(config)
print(b.register())




