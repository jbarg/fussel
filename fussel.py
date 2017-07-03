#!/usr/bin/python
# fussel.py is a stupid fuzzer. using pcap, scapy and radamsa

import scapy.all as scapy
from subprocess import Popen, PIPE
import ssl
import socket
import random
import time
import argparse
import sys
import os.path

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def is_valid_ip4(ip):
    # some rudimentary checks if ip is actually a valid IP
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)


def parse_args():
    parser = argparse.ArgumentParser(description='simple stupid pcap fuzzer')
    parser.add_argument('-t', '--target-ip', dest='target_ip', required=True, help='remote target IP')
    parser.add_argument('-p', '--target-port', dest='target_port', required=True, help='remote target port')
    parser.add_argument('-i', '--input-pcap', dest='input_pcap', required=True, help='input pcap file')
    parser.add_argument('-f', '--fuzz_factor', dest='fuzz_factor', required=False, help='fuzz factor, default: 50', default=50.0)
    parser.add_argument('-r', '--radamsa_path', dest='radamsa_path', required=False, help='path to radamsa binary', default='/usr/bin/radamsa')

    return parser.parse_args()

def print_buf(counter, buf):
    buf2 = [('%02x' % ord(i)) for i in buf]
    print '{0}: {1:<39}  {2}'.format(('%07x' % (counter * 16)),
        ' '.join([''.join(buf2[i:i + 2]) for i in range(0, len(buf2), 2)]),
        ''.join([c if c in string.printable[:-5] else '.' for c in buf]))


def hexdump(data, length=12):
    # this is a pretty hex dumping function directly taken from
    # http://code.activestate.com/recipes/142812-hex-dumper/
    result = []
    digits = 4 if isinstance(data, unicode) else 2

    for i in xrange(0, len(data), length):
        s = data[i:i + length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X   %-*s   %s" % (i, length * (digits + 1), hexa, text))
    print b'\n'.join(result)

def launch_radamsa(payload, radamsa_path):
    radamsa = [radamsa_path, '-n', '1', '-']
    p = Popen(radamsa, stdin=PIPE, stdout=PIPE)
    p.stdin.write(payload)
    p.stdin.close()
    p.wait()
    mutated_data = p.stdout.read()
    return mutated_data



def log_data(event, log_data):

    log_output = log_data = '\n'

    if event is 'fuzzing':
        try:
            file_d = open('fuzzing.log', 'a')

        except IOError as err:
            return "[!] Error opening log file: %s" % str(err)

    elif event is  'error':
        try:
            file_d = open('error.log', 'a')
        except IOError as err:
            return "[!] Error opening error file: %s" % str(err)

    if file_d:
        file_d.write(log_output)
    return



def main():

    clientsIP_list = []
    serversIP_list = []
    fuzz_list = []
    random.seed(time.time())


    '''
    parsing arguments
    '''
    args = parse_args()
    if not is_valid_ip4(args.target_ip):
        sys.exit(1)
    else:
        target_ip = args.target_ip


    if os.path.isfile(args.input_pcap):
        input_pcap_filename = args.input_pcap
    else:
        sys.exit(2)

    if os.path.isfile(args.radamsa_path):
        radamsa_path = args.radamsa_path
    else:
        sys.exit(3)
    fuzz_factor = args.fuzz_factor
    target_port = args.target_port



    print '[!] Analyizing PCAP: ' + input_pcap_filename
    packets = scapy.rdpcap(input_pcap_filename)
    print '[+] Identified %d packets in PCAP' % len(packets)
    time.sleep(1)

    count = 0
    for pkt in packets:

        ''' Only interested if pkt starts with SYN flag. Hosts sending SYN will be clients, the DstIP will be servers'''
        if count is 0:
            if pkt['TCP'].sprintf('%TCP.flags%') == 'S':
                clientsIP_list.append(pkt['IP'].src)
                serversIP_list.append(pkt['IP'].dst)
        count += 1

        try:
            if pkt['Raw']:
                '''
                Check for information flow direction. At this point, I am only interessted in mutating data send to the target.
                '''
                if pkt['IP'].src in clientsIP_list:
                    print '[+] Identified data to fuzz in packet: %d' % count
                    fuzz_list.append((count, str(pkt['Raw'])))

        except IndexError:
            continue


    fuzz_count = 0
    while True:
        print bcolors.OKGREEN + '[+] Fuzzing: %d ' % fuzz_count + bcolors.ENDC

        try:
            fuzz_count += 1

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ''' in case the server uses TLS '''
            sock.connect((target_ip, int(target_port)))
            #ssl_sock = ssl.wrap_socket(sock)
            #ssl_sock.connect((target_ip, int(target_port)))
            for pkt in fuzz_list:
                fuzz_payload = pkt[1]

                ''' fuzz payload? '''
                ran = random.random()
                if ran < float(fuzz_factor) / 100:
                    fuzz_payload = launch_radamsa(fuzz_payload, radamsa_path)
                #print '[!] Sending Payload: #%d \n' % fuzz_count
                log_data('fuzzing', fuzz_payload)
                hexdump(fuzz_payload, 16)
                sock.send(fuzz_payload)
                recv = sock.recv(2048)
            sock.close()

        except Exception as error:
            error_str = '[!!!] Error during fuzz iteration #%d\nError Message: %s' %(fuzz_count, str(error))
            print error_str

if __name__ == '__main__':
    main()

