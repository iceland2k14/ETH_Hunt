# -*- coding: utf-8 -*-
"""
@author: iceland

"""

import bit
import time
import binascii
import random
import sys
import ctypes
import os
# import re
import platform

from multiprocessing import Event, Process, Queue, Value, cpu_count

# =============================================================================
if platform.system().lower().startswith('win'):
    dllfile = 'ice_secp256k1.dll'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        ice = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
    
elif platform.system().lower().startswith('lin'):
    dllfile = 'ice_secp256k1.so'
    if os.path.isfile(dllfile) == True:
        pathdll = os.path.realpath(dllfile)
        ice = ctypes.CDLL(pathdll)
    else:
        print('File {} not found'.format(dllfile))
    
else:
    print('[-] Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
    sys.exit()

ice.privatekey_group_to_ETH_address.argtypes = [ctypes.c_char_p, ctypes.c_int] # pvk, m
ice.privatekey_group_to_ETH_address.restype = ctypes.c_void_p
ice.free_memory.argtypes = [ctypes.c_void_p] # pointer
ice.init_secp256_lib()
#==============================================================================

def privatekey_group_to_ETH_address(pvk_int, m):
    if m<=0: m = 1
    start_pvk = hex(pvk_int)[2:].encode('utf8')
    res = ice.privatekey_group_to_ETH_address(start_pvk, m)
    addrlist = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    ice.free_memory(res)
    return addrlist
#==============================================================================
eth_address_list = [line.split(',')[0] for line in open("eth_address.txt",'r')]
#eth_address_list = [re.split(r'[ ,|;"]+', line)[0] for line in open("eth2021_1_22_.txt",'r')]
eth_address_list = set(eth_address_list)

screen_print_after_keys = 100000

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

    print('Starting thread:', r, 'base: ',hex(key_int))

    while True:
        if match.is_set():
            return

        with counter.get_lock():
            counter.value += screen_print_after_keys

        
        current_pvk = key_int + k*screen_print_after_keys

        eth_addr = privatekey_group_to_ETH_address(current_pvk, screen_print_after_keys)
        

        if (k+1)%5 == 0:
#            print('checked ',k+1,' keys by Thread: ', r, 'Current ETH: ','0x'+eth_addr[-40:])
            print('[+] Total Keys Checked : {0}  [ Speed : {1:.2f} Keys/s ]  Current ETH: {2}'.format(counter.value, counter.value/(time.time() - st), '0x'+eth_addr[-40:]))
#        if eth_addr.startswith('0x00'):
        for t in range(screen_print_after_keys):
            this_eth = '0x'+eth_addr[t*40:t*40+40]
            if this_eth in eth_address_list:
                match.set()
                queue.put_nowait((current_pvk+t, this_eth))
                return
        
        k += 1



#==============================================================================


if __name__ == '__main__':
    print('[+] Starting.........Wait.....')
    hunt_ETH_address(cores=4)
    