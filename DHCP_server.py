import scapy.all as s
import time


class DHCP_server(object):
    def __init__(self):
        self.ip_pool = []
        self.ip_time = []
        self.file_name = 'DHCP_log.txt'

    def catch_packet(self):
        a = s.sniff(count=1,lfilter=lambda x:x.haslayer(s.DHCP))
        return a[0]
    
    def packet_responce(self, packet):
        if (message-type, 1) in packet[s.DHCP].options:
            print '%s this ia a discover packet' % time.time()
            print 'discover from MAC %s' % packet[s.Ether].src
            self.discover_responce(packet)
        elif (message-type, 2) in packet[s.DHCP].options:
            print '%s this is a offer packet' % time.time()
            print 'there has another DHCP server'
            self.offer_responce(packet)
        elif (message-type, 3) in packet[s.DHCP].options:
            print '%s this is a request packet' % time.time()
            print 'someone request a ip address'
            self.request_responce(packet)
        elif (messaget-type, 8) in packet[s.DHCP].options:
            print '%s this ia a inform packet' % time.time()
            print 'get the ip in the ip_list'
            self.inform_responce(packet)
        else:
            print 'this packet is not right'
            self.other_responce(packet)

        return 0
    
    def discover_responce(self, packet):
        pass

    def offer_responce(self, packet):
        pass

    def request_responce(self, packet):
        pass

    def inform_responce(self, packet):
        pass

    def other_responce(self, packet):
        pass

    def log_print(self, message):
        file = open(self.file_name, 'a')
        file.write('%s >>> %s' % (time.time(), message))
        file.write('\n')
        file.close()



