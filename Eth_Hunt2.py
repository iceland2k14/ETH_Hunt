# -*- coding: utf-8 -*-
"""
@author: iceland
Special Thanks to AlbertoBSD for a lot of help, always. :)
"""

import bit
import time
import binascii
import random
import sys
import gmp_ec as ec
import re

from eth_hash.auto import keccak

from multiprocessing import Manager, Event, Process, Queue, Value, cpu_count

#==============================================================================

eth_address_list = [line.split(',')[0] for line in open("eth_address.txt",'r')]
#eth_address_list = [re.split(r'[ ,|;"]+', line)[0] for line in open("eth2021_1_22_.txt",'r')]
eth_address_list = set(eth_address_list)

screen_print_after_keys = 100000
#==============================================================================

def ETH_Address(un_pubk_bytes):
    return '0x' + keccak(un_pubk_bytes[1:])[-20:].hex()

#==============================================================================
def hunt_ETH_address(cores='all'):  # pragma: no cover

    available_cores = cpu_count()

    if cores == 'all':
        cores = available_cores
    elif 0 < int(cores) <= available_cores:
        cores = int(cores)
    else:
        cores = 1

    counter = Value('L')
    match = Event()
    queue = Queue()
#    manager = Manager()

#    eth_address_dict = manager.dict({line.split()[0]:k for k, line in enumerate(open("eth2021_1_22_.txt",'r'))})

    workers = []
    for r in range(cores):
        p = Process(target=generate_key_address_pairs, args=(counter, match, queue, r))
        workers.append(p)
        p.start()

    for worker in workers:
        worker.join()

    keys_generated = 0
    while True:
        time.sleep(1)
        current = counter.value
        if current == keys_generated:
            if current == 0:
                continue
            break
        keys_generated = current
        s = 'Total Keys generated: {}\r'.format(keys_generated)

        sys.stdout.write(s)
        sys.stdout.flush()

    private_key, address = queue.get()
    print('\n\nPrivate Key(hex): ', hex(private_key))
    wif_key = bit.format.bytes_to_wif(binascii.unhexlify((hex(private_key)[2:]).zfill(64)))
    print('PrivateKey(wif): {}\n' 'ETH Address: {}'.format(wif_key, address))

#==============================================================================
def generate_key_address_pairs(counter, match, queue, r):  # pragma: no cover
    st = time.time()
    k = 0
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = random.randint(1,N)
    G = ec.G
    P = ec.Scalar_Multiplication(key_int, G)
    print('Starting thread:', r, 'base: ',hex(key_int))

    while True:
        if match.is_set():
            return

        with counter.get_lock():
            counter.value += 1

        
        current_pvk = key_int + k
        if k > 0:
            P = ec.Point_Addition(P, G)
        

        upub = bytes.fromhex(ec.Point_to_Pubkey(P, compressed=False))
        eth_addr = '0x' + keccak(upub[1:])[-20:].hex()

        if (k+1)%screen_print_after_keys == 0: 
#            print('checked ',k+1,' keys by Thread: ', r, 'Current ETH: ',eth_addr)
            print('[+] Total Keys Checked : {0}  [ Speed : {1:.2f} Keys/s ]  Current ETH: {2}'.format(counter.value, counter.value/(time.time() - st), eth_addr))
#        if eth_addr.startswith('0x00'):
        if eth_addr in eth_address_list:
            match.set()
            queue.put_nowait((current_pvk, eth_addr))
            return
        
        k += 1



#==============================================================================


if __name__ == '__main__':
    print('[+] Starting.........Wait.....')
    hunt_ETH_address(cores=4)
    
