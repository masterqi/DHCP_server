import scapy.all as s
import time
import binascii


class DHCP_server(object):
    def __init__(self):
        self.memory_mac = []
        self.offer_ip_list = []
        self.file_name = 'DHCP_log.txt'


    def catch_packet(self):
        a = s.sniff(count=1,lfilter=lambda x:x.haslayer(s.DHCP))
        return a[0]
    
    def packet_responce(self, packet):
        print 'packet_reaponce'
        if ('message-type', 1) in packet[s.DHCP].options:
            print '%s this ia a discover packet' % time.time()
            print 'discover from MAC %s' % packet[s.Ether].src
            self.discover_responce(packet)
        elif ('message-type', 2) in packet[s.DHCP].options:
            print '%s this is a offer packet' % time.time()
            print 'there has another DHCP server'
            self.offer_responce(packet)
        elif ('message-type', 3) in packet[s.DHCP].options:
            print '%s this is a request packet' % time.time()
            print 'someone request a ip address'
            self.request_responce(packet)
        else:
            print 'this packet is not right'
            self.other_responce(packet)

        return 0
    
    def discover_responce(self, packet):
        offer_packet = s.Ether()/s.IP()/s.UDP()/s.BOOTP()/s.DHCP()
        discover_mac = ''
        offer_ip = ''
        for i in packet[s.DHCP].options:
            if len(i) == 2:
                if 'client_id' in i:
                    discover_mac = binascii.hexlify(i[1])
                    discover_mac = discover_mac[2:4] + ':' + discover_mac[4:6] + ':' +discover_mac[5:8] +':' +discover_mac[8:10] + ':' +\
                                   discover_mac[10:12] + ':' +discover_mac[12:]
                    discover_mac = discover_mac.upper()
                    break
        
        if len(discover_mac) > 0:
            if len(self.memory_mac) > 0:
                for i in self.memory_mac:
                    if i['mac'] == discover_mac:
                        if i['ip'] not in self.offer_ip_list:
                            offer_ip =  i['ip']
            if len(offer_ip) > 0:
                pass
            else:
                offer_ip = self.ip_next()
            if len(offer_ip) > 1:
                offer_packet[s.IP].dst = offer_ip
                offer_packet[s.BOOTP].yiaddr = offer_ip
                offer_packet[s.Ether].dst = packet[s.Ether].src
                offer_packet[s.UDP].dport = packet[s.UDP].sport
                offer_packet[s.UDP].sport = packet[s.UDP].dport
                offer_packet[s.BOOTP].xid = packet[s.BOOTP].xid
                offer_packet[s.BOOTP].op = 'BOOTREPLY'
               
                for i in packet[s.DHCP].options:
                    if len(i) == 2:
                        if 'param_req_list' in i:
                            req_list = binascii.hexlify(i[1])
                            req_list_int = []
                            a = len(req_list)
                            a = a/2
                            for j in range(1,a):
                               x = j - 1
                              
                               y = int(req_list[x*2:j*2], 16)
                               req_list_int.append(y)
                               print req_list_int
                            offer_packet[s.DHCP].options = self.req_options(req_list_int, 2)
               
                s.sendp(offer_packet,count=1)
            else:
                self.log_print('DHCP POOL HAS NOT IP FOR OFFER')
                return 0
        else:
            self.log_print('DHCP server is error or the packet is error')
            return 0 
                
    def req_options(self, req_list, messagetype):
        if messagetype == 2:
            options_list=[('message-type', 2)]
        elif messagetype == 5:
            options_list=[('message-type', 5)]
        else:
            self.log_print('the DHCP server is not right')
    	for req_options in req_list:
            print req_options
    	    if req_options == 1:
    	        options_message = ('subnet_mask', self.subnet_mask)
            elif req_options == 3:
    	       
    	        options_message = ('router', self.router)
    	    elif req_options == 6:
    	       
    	        options_message = ('name_server', self.name_server)
    	    elif req_options == 51:
    	       
    	        options_message = ('lease_time', self.lease_time)
    	    elif req_options == 54:
    	    	
    	    	options_message = ('server_id', self.server_ip)
    	    else:
    	        options_message = ''
    	    if len(options_message):
    	        options_list.append(options_message)
    	    else:
    	    	pass
    	options_list.append('end')
    	return options_list

    def ip_next(self):
    	list_ip = 1
        if len(self.offer_ip_list) == 0:
            self.offer_ip_last = self.ip_start
            return self.offer_ip_last
        else:
            while list_ip:
                a = self.offer_ip_last.rfind('.')
                b = int(self.offer_ip_last[a+1:]) + 1
                c = self.ip_stop.rfind('.')
                d = int(self.ip_stop[c+1:]) + 1
                if b < min(d, 255):
                    offer_ip_last_1 = self.offer_ip_last[0:a] + ':' + ('%d' % b)
                else:
                    list_ip = 0
                    offer_ip_last_1 = ''
                if offer_ip_last_1 in self.offer_ip_list:
                    self.offer_ip_last = offer_ip_last_1
                else:
                    liset_ip = 0
                    self.offer_ip_last = offer_ip_last_1
            if len(offer_ip_last_1):
                return self.offer_ip_last
            else:
                return 0

    def offer_responce(self, packet):
        a = s.Ether()
        host_mac = a.src.upper()
        if packet[s.Ether].src.upper() is not host_mac:
            self.offer_ip_list.append(packet[s.BOOTP].yiaddr)
            b = {}
            b['mac'] = a
            b['ip'] = packet[s.BOOTP].yiaddr
            if b in memory_mac:
                pass
            else:
                self.memory_mac.append(b)
            for i in packet[s.DHCP].options:
                if len(i) == 2:
                    if 'server_id' in i:
                        self.log_print('there is another DHCP server and server ip is %s' % i[1])
        else:
            pass
        return 0

    def request_responce(self, packet):
        a = self.ip_start.rfind('.')
        b = self.ip_start[0:a]
        for i in packet[s.DHCP].options:
            if len(i) == 2:
                if 'client_id' in i:
                    request_mac = binascii.hexlify(i[1])
                    request_mac = request_mac[2:4] + ':' + request_mac[4:6] + ':' +request_mac[5:8] +':' +request_mac[8:10] + ':' +\
                                   request_mac[10:12] + ':' +request_mac[12:]
                    request_mac = request_mac.upper()
                elif 'requested_addr' in i:
                    request_ip = i[1]
                    e = request_ip.rfind('.')
                    f = request_ip[0:e]
                    if (request_ip in self.offer_ip_list) or (b != f):
                        ack_nck = False
                    else:
                         ack_nck =True
                elif 'server_ip' in i:
                    req_server_ip = i[1]
                    if req_server_ip == self.server_ip:
                        ack_nck = True
                    else:
                        ack_nck = False
                elif 'host_name' in i:
                    req_host_name = i[1]
                elif 'param_req_list' in i:
                    req_req_list = binascii.hexlify(i[1])
                    req_req_list_int = []
                    c = len(req_list)
                    c = c/2
                    for j in range(0,c):
                        x = j - 1
                        y = int(req_list[x*2:j*2], 16)
                        req_req_list_int.append(y)
                else:
                    pass
        if ack_nck:
            self.offer_ip_list.append(request_ip)
            d = {}
            d['mac'] = request_mac
            d['ip'] = request_ip
            self.memory_mac.append(d)
            ack_packet = s.Ether()/s.IP()/s.UDP()/s.BOOTP()/s.DHCP()
            ack_packet[s.Ether].dst = packet[s.Ether].src
            ack_packet[s.IP].dst = request_ip
            ack_packet[s.UDP].sport = packet[s.UDP].dport
            ack_packet[s.UDP].dport = packet[s.UDP].sport
            ack_packet[s.BOOTP].xid = packet[s.BOOTP].xid
            ack_packet[s.BOOTP].yiaddr = request_ip
            ack_packet[s.DHCP].options = slef.req_options(req_req_list_int, 5)
            sendp(ack_packet, count=1)
        else:
            nak_packet = s.Ether()/s.IP()/s.UDP()/s.BOOTP()/s.DHCP()
            nak_packet[s.Ether].dst = packet[s.Ether].src
            nak_packet[s.UDP].sport = packet[s.UDP].dport
            nak_packet[s.UDP].dport = packet[s.UDP].sport
            nak_packet[s.BOOTP].xid = packet[s.BOOTP].xid
            nak_packet[s.BOOTP].options = [('message-type', 6), 'end']
            sendp(nak_packet, count=1)
        return 0

    def other_responce(self, packet):
        self.log_print('this packet can not be deal : %s' % packet)
        return 0

    def log_print(self, message):
        file = open(self.file_name, 'a')
        file.write('%s >>> %s' % (time.time(), message))
        file.write('\n')
        file.close()

    def dhcp_server_single(self, ip_start_1, ip_stop_1, router_1, name_server_1, lease_time_1=7200, subnet_mask_1='255.255.255.0'):
        '''
        ip_start_1: the ip pool start
        ip_stop_1: the ip_pool stop
        lease_time_1:the ip lease time
        subnet_mask_1:the subnet mask(default is 255.255.255.0)
        router_1:the router ip
        name_server_1:the name server ip
        '''
        self.ip_start = ip_start_1
        self.ip_stop = ip_stop_1
        self.lease_time = lease_time_1
        self.subnet_mask = subnet_mask_1
        self.router = router_1
        self.name_server = name_server_1
        a = s.IP()
        self.server_ip = a[s.IP].src
        b = self.ip_start.rfind('.')
        c = self.ip_stop.rfind('.')
        d = self.server_ip.rfind('.')
        if self.ip_start[0:b] == self.ip_stop[0:c] == self.server_ip[0:d]:
            while True:
                packet = self.catch_packet()
                self.packet_responce(packet)
        else:
            return 0

guo = DHCP_server()
guo.dhcp_server_single('192.168.0.100', '192.168.0.199', '192.168.0.1', '192.168.0.1')
         
