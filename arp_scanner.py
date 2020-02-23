#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import argparse
import time
import subprocess
import os
from colorama import init, Fore		# for fancy/colorful display

class Scanner:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.Yellow = Fore.YELLOW
        self.Blue = Fore.BLUE
        self.RESET = Fore.RESET

    def arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', dest='target', help='Target IP / IP Range')
        value = parser.parse_args()
        if not value.target:
            parser.error('\n{}[-] Please Specify The Target {}'.format(self.Yellow, self.RESET))
        return value

    def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_broadcast = broadcast / arp_request
        answered_list, unanswered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)
        clients = []
        for element in answered_list:
            d = {'ip':element[1].psrc, 'mac':element[1].hwsrc}
            clients.append(d)
        return clients

    def display(self, hosts):
        print('\n{}[*] Scanning...\n{}'.format(self.GREEN, self.RESET))
        time.sleep(1)
        print('\n{}IP Address\t\t\tMAC Address {}'.format(self.Yellow, self.RESET))
        print('{}-----------------------------------------------------{}'.format(self.Blue, self.RESET))
        for client in hosts:
            print(client['ip'] + "\t\t\t" + client['mac'])
        print('\n')

    def start(self):
        options = self.arguments()
        if 'nt' in os.name:
            subprocess.call('cls', shell=True)
        else:
            subprocess.call('clear', shell=True)

        print('{}\n\n\t\t\t\t\t\t#########################################################{}'.format(self.Cyan, self.RESET))
        print('\n{}\t\t\t\t\t\t#\t            A R P Network Scanner\t\t#\n{}'.format(self.Cyan, self.RESET))
        print('{}\t\t\t\t\t\t#########################################################{}\n\n'.format(self.Cyan, self.RESET))

        start_time = time.time()
        clients = self.scan(options.target)
        self.display(clients)
        stop_time = time.time()
        total_time = stop_time - start_time

        print('\n{}[*] Scan Complete!{}'.format(self.RED, self.RESET))
        print('{}[*] Scan Duration: {}'.format(self.GREEN, self.RESET) + str(total_time) + '\n\n')

if __name__ == "__main__":

    arp_scanner = Scanner() # class object
    arp_scanner.start()

