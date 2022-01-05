# -*- coding: utf-8 -*-
"""
@author: iceland

"""
#import bit
import time
#import binascii
import random
# import re
import secp256k1 as ice

from multiprocessing import Event, Process, Queue, Value, cpu_count


#==============================================================================
eth_address_list = [line.split()[0].lower() for line in open("eth_address.txt",'r')]
#eth_address_list = [re.split(r'[ ,|;"]+', line)[0] for line in open("eth2021_1_22_.txt",'r')]
eth_address_list = set(eth_address_list)

group_size = 1000000
#==============================================================================
    
def hunt_ETH_address(cores='all'):  # pragma: no cover

    try:
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
    
    except(KeyboardInterrupt, SystemExit):
        exit('\nSIGINT or CTRL-C detected. Exiting gracefully. BYE')

    
    private_key, address = queue.get()
    print('\n\nPrivate Key(hex):', hex(private_key))
    wif_key = ice.btc_pvk_to_wif(private_key, False)
#    wif_key = bit.format.bytes_to_wif(binascii.unhexlify((hex(private_key)[2:]).zfill(64)))
    print('Private Key(wif): {}\n' 'ETH Address:      {}'.format(wif_key, address))

#==============================================================================
def generate_key_address_pairs(counter, match, queue, r):  # pragma: no cover
    st = time.time()
#    k = 0
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = random.SystemRandom().randint(1,N)

    P = ice.scalar_multiplication(key_int)
    current_pvk = key_int + 1   # because sequential increments adds G, 2G, 3G, .... 
    
    print('Starting thread:', r, 'base: ',hex(key_int))

    while True:
        try:
            if match.is_set():
                return
    
            with counter.get_lock():
                counter.value += group_size
    
            
            Pv = ice.point_sequential_increment(group_size, P)
    
            for t in range(group_size):
                this_eth = ice.pubkey_to_ETH_address(Pv[t*65:t*65+65])
                if this_eth in eth_address_list:
    #            if this_eth.startswith('0x00'):
                    match.set()
                    queue.put_nowait((current_pvk+t, this_eth))
                    return
            
            if (counter.value)%group_size == 0:
                print('[+] Total Keys Checked : {0}  [ Speed : {1:.2f} Keys/s ]  Current ETH: {2}'.format(counter.value, counter.value/(time.time() - st), this_eth))
    
            
            P = Pv[-65:]
            current_pvk += group_size
        
        except(KeyboardInterrupt, SystemExit):
            break


#==============================================================================


if __name__ == '__main__':
    print('[+] Starting.........Wait.....')
    hunt_ETH_address(cores = 8)
    