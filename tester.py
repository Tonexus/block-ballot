import time
import json
import argparse
import pickle
import threading
import subprocess
import xmlrpc.client

from ballot import Ballot

import putil

def print_processor_wallets(issuer, keys):
	balances = issuer.get_winner()
	print('Balances of voters')
	for key in keys:
		print('--- Voter balance is --- ', balances.get(key, {}).get('balance', 404))
		balances[key] = None
	print('Balances of processors and Issuer')
	for pk in balances:
		if balances[pk] is not None:
			print('--- Issuer/Processor balance is --- ', balances[pk]['balance'])

def client(config, voter_keys, index):
    ballots = []
    for i in range(12):
        ballots.append(Ballot(config))
        print("Thread {} registering ballot {}".format(index, i))
        ballots[i].register()
        voter_keys.append(ballots[i].public_hex)

    for i in range(len(ballots)):
        print("Thread {} ballot {} votes for {}".format(index, i, 0))
        ballots[i].vote(ballots[0].public)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="set config file")
    args = parser.parse_args()

    if args.config:
        print("Set config file to %s" % args.config)
    else:
        exit()

    with open(args.config, 'r') as f:
        config = json.load(f)

    # create issuer process
    procs = [subprocess.Popen(
        ["python3", "run_issuer.py", "-c", args.config],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )]

    try:
        # create processor processes
        for i in range(len(config['nodes'])):
            procs.append(subprocess.Popen(
                ["python3", "run_processor.py", "-c", args.config, "-i", str(i)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ))
        print("Waiting 3 seconds for processes to start")
        time.sleep(3)

        print(len(procs), " processes online")

        config = {
            'issuer_address': config['processor_config']['config']['issuer_address'],
            'node_addresses': config['nodes']
        }

        issuer = xmlrpc.client.ServerProxy(config['issuer_address'], allow_none=True)

        print("Election started: ", issuer.start_election())
        
        voter_keys = []
        
        threads = []
        for i in range(3):
            threads.append(threading.Thread(target=client, args=(config, voter_keys, i)))
            threads[i].start()
        for thread in threads:
            thread.join()

        balances = issuer.get_winner()

        processor = xmlrpc.client.ServerProxy(config['node_addresses'][0], allow_none=True)
        print("Length blockchain: {}".format(len(pickle.loads(processor.get_blockchain().data))))
        print_processor_wallets(issuer, voter_keys)
    finally:
        # clean up processes if error
        for proc in procs:
            proc.kill()

    # clean up processes
    for proc in procs:
        proc.kill()
