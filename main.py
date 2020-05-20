from issuer_rpc import serve_issuer
print("Hello World")

config = {}
config['node_addresses'] = []
config['pow_config'] = 'pow config'
serve_issuer(config, 12345)