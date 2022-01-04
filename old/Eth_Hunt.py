# -*- coding: utf-8 -*-
"""
@author: iceland
"""

import bit
import time
import binascii
import random
import sys

from eth_hash.auto import keccak
from fastecdsa import curve
from fastecdsa.point import Point

from multiprocessing import Event, Process, Queue, Value, cpu_count

#==============================================================================

eth_address_list = [line.split()[0] for line in open("eth_address.txt",'r')]
eth_address_list = set(eth_address_list)
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

    counter = Value('i')
    match = Event()
    queue = Queue()
    

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
        s = 'Keys generated: {}\r'.format(keys_generated)

        sys.stdout.write(s)
        sys.stdout.flush()

    private_key, address = queue.get()
    print('\n\nPrivate Key(hex): ', hex(private_key))
    wif_key = bit.format.bytes_to_wif(binascii.unhexlify((hex(private_key)[2:]).zfill(64)))
    print('PrivateKey(wif): {}\n' 'ETH Address: {}'.format(wif_key, address))

#==============================================================================
def generate_key_address_pairs(counter, match, queue, r):  # pragma: no cover

    k = 0
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = random.randint(1,N)
    G = curve.secp256k1.G
    x1, y1 = bit.format.public_key_to_coords(bit.Key.from_int(key_int).public_key)
    P = Point(x1,y1, curve=curve.secp256k1)
    print('Starting thread:', r, 'base: ',hex(key_int))

    while True:
        if match.is_set():
            return

        with counter.get_lock():
            counter.value += 1

        
        current_pvk = key_int + k
        if k > 0:
            P += G
        
        upub = bit.format.point_to_public_key(P, compressed=False)
        eth_addr = '0x' + keccak(upub[1:])[-20:].hex()

        if (k+1)%100000 == 0: print('checked ',k+1,' keys by Thread: ', r, 'Current ETH: ',eth_addr)
#        if eth_addr.startswith('0xee'):
        if eth_addr in eth_address_list:
            match.set()
            queue.put_nowait((current_pvk, eth_addr))
            return
        
        k += 1



#==============================================================================


if __name__ == '__main__':
    hunt_ETH_address(cores=8)
    