# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
#from ryu.lib.packet import extended_tcp
#from ryu.lib.packet import bgp
from ryu.lib.packet import stream_parser
from ryu.lib import pcaplib
import socket, sys
from struct import * #to use unpack
from datetime import datetime

hasBuffer = 0
bgpSpeakerIp = '192.168.1.120'
#bgpSpeakerIp = '10.208.6.120'
port = 3000

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.remaining_buffer = {}
        self.remaining_buffer_type = {}
        self.total_path_attribute_len = 0
        self.bgp_length = 0
        self.bgp_message_sum = 0
        self.buffer_next_packet = 0
        self.bgp_total_path_att_len = 0
        self.bgp_type = 0
        self.bgp_header_end = 0
        self.path_attributes = {}
        self.previous_buffer_len = 0
        self.packet_number = 0
        self.ack_number = 0
        self.seq_number_set = set()
        self.next_seq = 0
        self.packet_seq_list = []
        self.buffer_dictionary = {}
        self.enable_check_next_tcp_sequence = 0
        self.total_number_prefixes = 0
        self.accepted_prefixes_set = set()
        self.remaining_nlri = {}
	self.is_update = 0
	self.mac_dst = {}
	self.mac_src = {}
	self.num_packets = 0
	self.start_time = 0
	self.send_announcement = 0

	f = open('/home/ubuntu/update_file.txt','w')
	f.close() 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        #match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        #actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        #self.add_flow(datapath, 0, match, actions)

        mux_ip = "100.78.128.1"

        match2 = parser.OFPMatch(eth_type=0x800,ipv4_src=mux_ip)
        actions2 = [parser.OFPActionSetField(ipv4_src=mux_ip),
                   parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 2, match2, actions2)
        
        match3 = parser.OFPMatch(eth_type=0x800,ipv4_dst=mux_ip)
        actions3 = [parser.OFPActionSetField(ipv4_dst=mux_ip),
                   parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 2, match3, actions3)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

  	self.logger.info("len(msg.data): %d",len(msg.data))

	self.parse_packet(ev.msg)
	self.logger.info("self.is_update: %d",self.is_update)

	if self.is_update == 1:
		self.is_update = 0
		return

	#if self.is_update == 1 and len(msg.data) > 89:
	#	self.is_update = 0
	#	return

	#if len(msg.data) <= 89:
	#	self.is_update = 0
	
        #pkt = packet.Packet(msg.data)
        #eth = pkt.get_protocols(ethernet.ethernet)[0]

        #if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
        #    return

	src = self.mac_src
	dst = self.mac_dst 
        #dst = eth.dst
        #src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in switch s%s in_port:%s - Src: %s -> Dst: %s", dpid, in_port, src, dst)

	pkt = packet.Packet(msg.data)
	p_arp = self.find_protocol(pkt, "arp")
	flood_arp_reply = 0

	if p_arp:
		if p_arp.opcode == arp.ARP_REPLY:
			self.logger.info("--- PacketIn: ARP_Reply: %s -> %s", src, dst)
			flood_arp_reply = 1

	#ip = pkt.get_protocol(ipv4.ipv4)

	#tcp_protocol = pkt.get_protocol(tcp.tcp)
             
        #if tcp_protocol != None:
        #    src_port = tcp_protocol.src_port
        #    dst_port = tcp_protocol.dst_port
        
        #    if src_port == 179 or dst_port == 179:
        #        total_len = ip.total_length
                #if total_len > 60:    
                #self.parse_packet(ev.msg)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

	if flood_arp_reply == 1:
		out_port = ofproto.OFPP_FLOOD	

        actions = [parser.OFPActionOutput(out_port)]
	self.logger.info("Out_port: %s", str(out_port))

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
	self.logger.info("datapath.send_msg(out)")
        datapath.send_msg(out)

    def parse_packet(self,message):
        self.logger.info("***************************************")
	if len(message.data) > 0:
		self.logger.info("len(message.data) > 0")
	elif len(message.data) == 0:
		self.logger.info("len(message.data) == 0")
        #pkt = packet.Packet(message.data)
	self.sniff_packet_2(message.data)

    def find_protocol(self,msg,name):
	for p in msg.protocols:
		if hasattr(p, 'protocol_name'):
			if p.protocol_name == name:
				return p

    def sniff_packet_2(self,packet):     
        #parse ethernet header
        eth_length = 14
        
        add_nlri_to_bgp_iterator = 0
        enable_bgp_iterator_total_increment = 0
     
        eth_header = packet[:eth_length]
        #self.logger.info("Crossed error from here")
                
        eth = unpack('!6s6sH' ,eth_header)
        eth_protocol = socket.ntohs(eth[2])
        self.packet_number = self.packet_number + 1
        self.logger.info("PACKET NUMBER: %d",self.packet_number)
	self.as_path_list_str = ""

        self.num_packets = self.num_packets + 1
        self.logger.info("self.num_packets: %d",self.num_packets)

        #if self.num_packets == 19000:
	if self.num_packets == 490:
            msg = "neighbor 100.78.128.1 announce route 184.164.227.0/24 next-hop self origin egp"
	    #msg = "Testing BGP message VM 2"
            #self.sendMessage(msg)

	print(' Source MAC : ' + self.eth_addr(packet[6:12]) + 'Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Protocol : ' + str(eth_protocol))
	self.mac_src = self.eth_addr(packet[6:12])
	self.mac_dst = self.eth_addr(packet[0:6])
 
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            #Parse IP header
            #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]
         
            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
 
            iph_length = ihl * 4
            tos = iph[1]
            total_len = iph[2]
 
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
 
            #print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' Type of Service (TOS) : ' + str(tos) + ' Total Length : ' + str(total_len) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
 #TCP protocol
            if protocol == 6 :
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
 
                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)
             
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
             
                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))    
                    
                #if self.ack_number != 0:
                #    if self.ack_number != acknowledgement:
                #        self.logger.info("Packet with ack number different from previous ack packets")
                #        return
                #else:
                #     self.logger.info("self.ack_number == %d",self.ack_number)
                
                    
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
             
                #get data from the packet
                data = packet[h_size:]
             
                #print('Data : ' + data)
                
                b = iph_length + eth_length + tcph_length * 4
                
                ip_len = b - 14
                packet_total_len = ip_len
                updated_packet_total_len = 0
            
                bgp_iterator = 0 #iterates through the TCP data according to the number of BGP messages
                
                #if len(packet) == 89:
                #    self.logger.info("len(packet) == 89")
                #    return
            
                tcp_data_len = len(packet)-b
                #self.logger.info("TCP Data Len: %d",tcp_data_len)
                tcp_data = packet[b:b+tcp_data_len]
                has_tcp_sequence = 0                
                    
                if tcp_data_len > 0:
                    if sequence in self.seq_number_set:
                        self.logger.info("[DUPLICATED SEQUENCE NUMBER]-TCP retransmission of previous sent segment!")
			self.is_update = 1
                        return
                    #if len(packet) == 89:
                        #if len(self.remaining_buffer) > 0:
                            #self.logger.info("len(packet) == 89 and len(self.remaining_buffer) > 0")
                            #return
                    if tcp_data_len == 19:
                        nlriNextByte = ""                        
                        nlri_next_byte = packet[b:b+2]
                        nlriNextByte = unpack('!ss',nlri_next_byte)
                        #self.logger.info("nlriNextByte [0]: %s [1]: %s",nlriNextByte[0],nlriNextByte[1])                            
                        if nlriNextByte[0] == nlriNextByte[1]:
                            self.logger.info("TCP data==19 -> KEEPALIVE message!")
                            if self.next_seq == sequence:
                                #self.logger.info("self.next_seq == sequence, as expected (%d)",self.next_seq)
                                self.next_seq = sequence+tcp_data_len
                            return
                        #else:
                            #self.logger.info("nlriNextByte != ('\xff',)")
                    #self.logger.info("New TCP sequence number Added to SET")
                    self.seq_number_set.add(sequence)
                    self.logger.info("self.buffer_dictionary: %d",len(self.buffer_dictionary))
                    if self.remaining_buffer_type !={} or self.enable_check_next_tcp_sequence == 1:
                        #if self.remaining_buffer_type !={}:
                        #    self.logger.info("self.remaining_buffer_type !={}")
                        #if self.enable_check_next_tcp_sequence == 1:
                        #    self.logger.info("self.enable_check_next_tcp_sequence == 1")
                    #if len(self.remaining_buffer) > 0 and self.remaining_buffer_type !={}:
                        self.enable_check_next_tcp_sequence = 1
                        #self.logger.info("self.enable_check_next_tcp_sequence <--- 1")
                        if self.next_seq == sequence:                            
                            #self.logger.info("self.next_seq == sequence, as expected (%d)",self.next_seq)
                            self.next_seq = sequence+tcp_data_len
                            #self.logger.info("Next TCP sequence number: %d",self.next_seq)
                            pck_next_seq_number = self.buffer_dictionary.get(self.next_seq)
                            while pck_next_seq_number != None:
                                #self.logger.info("pck_next_seq_number: %d",self.next_seq)
                                self.buffer_dictionary.pop(self.next_seq)
                                packet = packet + pck_next_seq_number
                                #self.logger.info("New packet len: %d",len(packet))
                                self.next_seq = self.next_seq + len(pck_next_seq_number)
                                #self.logger.info("Next TCP sequence number: %d",self.next_seq)
                                pck_next_seq_number = self.buffer_dictionary.get(self.next_seq) 
                            self.logger.info("self.buffer_dictionary: %d",len(self.buffer_dictionary)) 
                            has_tcp_sequence = 1
                        else:
                            if tcp_data_len > 0: #random chosen value. Previously it was 19, but packets with smaller lengths appeared.
                            #if tcp_data_len > 19:
                                #self.logger.info("TCP sequence number is not the expected. Packet will be added to the dictionary.")
                                if self.buffer_dictionary.get(sequence) == None:
                                    #self.logger.info("Packet not seen yet. It will be added to the dictionary.")
                                    self.buffer_dictionary[sequence] = tcp_data
                                    return
                                else:
                                    #self.logger.info("Packet found in dictionary. Will parse this packet.")
                                    self.logger.info("self.buffer_dictionary: %d",len(self.buffer_dictionary))
                                    self.next_seq = sequence+tcp_data_len
                                    #self.logger.info("Next TCP sequence number: %d",self.next_seq)
                                    has_tcp_sequence = 1                                  
                                #self.packet_seq_list.append(sequence)
                                #self.logger.info("self.packet_seq_list: %d",len(self.packet_seq_list))
                                #adds the pair {sequence,packet} to the dictionary
                                
                    if len(self.buffer_dictionary) == 0 and has_tcp_sequence == 0:
                        self.next_seq = sequence+tcp_data_len
                        #self.logger.info("Next TCP sequence number: %d",self.next_seq)
                
                #if total_len > b: #There is TCP data      
                #self.logger.info("remaining_buffer length before: %d", len(self.remaining_buffer))
                
                has_buffer_from_previous_packet = 0
                if len(self.remaining_buffer) > 0:
                    has_buffer_from_previous_packet = 1
                    #self.logger.info("has_buffer_from_previous_packet <- 1")
                         
                while packet_total_len < len(packet)-14:
                    #self.logger.info("packet_total_len: %d ---- total_len IP: %d---- total_len Packet: %d",packet_total_len,total_len,len(packet)-14) 
                    
                    type_unfeasible_len_before_buffer_len_zero = 0 #Used to update bgp_iterator after NLRI parse when remaining_buffer == 0  
                 
                    if b+bgp_iterator + 19 > len(packet) or (len(packet)-14 - ip_len < 19) :                 
                    #if b+bgp_iterator + 19 > total_len + 14:
                        #self.logger.info("Packet size reached")   
                        
                        remaining_packet_size =  len(packet) - (b+bgp_iterator)
                        #self.logger.info("Remaining Packet size: %d", remaining_packet_size) 
                        
                        if remaining_packet_size == 0:
                            return    
                        
                        if self.remaining_buffer_type != 'attribute' and self.remaining_buffer_type != 'nlri':
                            #remaining_packet_size =  (total_len + 14) - (b+bgp_iterator)
                            
                            #self.remaining_buffer = packet[packet_total_len:packet_total_len+remaining_packet_size]
                        
                            #self.logger.info("len(packet)-14 - ip_len: %d", len(packet)-14 - ip_len)
                            if (len(packet)-14 - ip_len < 19):
                                #if self.bgp_total_path_att_len < len(self.path_attributes):
                                self.remaining_buffer = self.remaining_buffer + packet[b+bgp_iterator:b+bgp_iterator+remaining_packet_size]
                                return
                            
                            self.remaining_buffer = packet[b+bgp_iterator:b+bgp_iterator+remaining_packet_size]
                            #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer)) 
                            self.remaining_buffer_type = 'header'
                        
                            if len(self.remaining_buffer) >= 18:                       
                                bgph = unpack('!QQh',self.remaining_buffer)
                                self.bgp_length = bgph[2]                        
                                #self.logger.info("BGP Test Length: %s", str(self.bgp_length))                        
                            return
                    #if len(self.remaining_buffer) > 0:
                    if self.remaining_buffer_type == 'header':
                        new_packet = packet[0:b] + self.remaining_buffer + packet[b:len(packet)]
                        packet = new_packet
                        #self.logger.info("Formed BGP message from remaining BGP header from previous packet.")
                        self.previous_buffer_len = len(self.remaining_buffer)
                        self.remaining_buffer = {}
                        self.remaining_buffer_type = {}
                        #self.logger.info("len(self.remaining_buffer)== %d",len(self.remaining_buffer))
                    
                    if self.remaining_buffer == {} or self.remaining_buffer_type == 'nlri' or self.remaining_buffer_type == 'attribute' or self.remaining_buffer_type == 'unfeasible' or self.remaining_buffer_type == 'update_header':
                        if self.remaining_buffer_type != 'nlri':
                            if self.remaining_buffer_type != 'attribute' and self.remaining_buffer_type != 'update_header' and self.remaining_buffer_type != 'unfeasible':    
                                #self.logger.info("self.previous_buffer_len: %d", self.previous_buffer_len)
                                #self.logger.info("bgp_iterator: %d", bgp_iterator)
                                bgp_header = packet[b+bgp_iterator:19+b+bgp_iterator]
                                #self.logger.info("b+bgp_iterator: %d",b+bgp_iterator)
                                bgph = unpack('!QQhb',bgp_header)
                                self.bgp_message_sum = 0
                                self.bgp_length = bgph[2]
                                self.bgp_type = bgph[3]
                                self.bgp_header_end = b + 19 + bgp_iterator
                                #self.logger.info("BGP Length: %s", str(self.bgp_length))
                                #self.logger.info("BGP Type: %d", self.bgp_type)
                    
                                if self.bgp_length == 0:
                                    return
                                
                                if self.bgp_type < 1 and self.bgp_type > 4:
                                    self.logger.info("INVALID BGP Type!")
                    
                                packet_total_len = packet_total_len + self.bgp_length
                                updated_packet_total_len = 1
                                bgp_iterator = bgp_iterator + self.bgp_length
                                #self.logger.info("bgp_iterator + self.bgp_length: %d", bgp_iterator)
                    
                                self.bgp_message_sum = self.bgp_message_sum + 19
                    
                                if self.bgp_type == 1:
                                    self.logger.info("BGP Type: 1-OPEN")
                                    bgp_open = packet[self.bgp_header_end:10+self.bgp_header_end]
                                    bgpopen = unpack('!bHH4sB',bgp_open)
                                    bgp_version = bgpopen[0]
                                    bgp_myAS = bgpopen[1]
                                    bgp_holdTime = bgpopen[2]
                                    bgp_identifier = socket.inet_ntoa(str(bgpopen[3]))
                                    bgp_opt_par_len = bgpopen[4]
                                    #self.logger.info("BGP Version: %s", str(bgp_version))
                                    #self.logger.info("BGP MyAS: %s", str(bgp_myAS))
                                    #self.logger.info("HoldTime: %s", str(bgp_holdTime))
                                    #self.logger.info("BGP Identifier: %s", str(bgp_identifier))
                                    #self.logger.info("(BGP Identifier len: %d)", len(str(bgpopen[3])))
                                    #self.logger.info("BGP Optional Parameter Length: %s", str(bgp_opt_par_len))
                                elif self.bgp_type == 2:
                                    #if self.ack_number == 0 and len(packet)>=1311:
                                    #    self.ack_number = acknowledgement
                                    #    self.logger.info("Set self.ack_number!")
                                    #elif self.ack_number != acknowledgement:
                                    #    self.logger.info("Packet with ack number different from previous ack packets")
                                    #    return
                        
                                    #self.logger.info("BGP Type: 2-UPDATE")
                                    if self.bgp_header_end+2 > len(packet):
                                        #self.logger.info("Packet size reached before unfeasible routes len")
                                        type_unfeasible_len_before_buffer_len_zero = 1
                                        #remaining_packet_size = len(packet) - self.bgp_header_end+4+int(bgpunfeasiblelen2[0])
                                        remaining_packet_size = len(packet) - (self.bgp_header_end)
                                        #self.logger.info("Remaining Packet size: %d", remaining_packet_size)
                                        self.remaining_buffer_type = 'unfeasible'
                                        if remaining_packet_size == 0:
                                            self.remaining_buffer = {}
                                        else:
                                            self.remaining_buffer = packet[self.bgp_header_end:self.bgp_header_end+remaining_packet_size]
                                        return
                                        
                                    bgp_unfeasible_routes_len = packet[self.bgp_header_end:self.bgp_header_end+2]
                                    bgpunfeasiblelen = unpack('!H',bgp_unfeasible_routes_len)
                                    bgpunfeasiblelen1 = str(bgpunfeasiblelen).split('(')
                                    bgpunfeasiblelen2 = str(bgpunfeasiblelen1[1]).split(',')
                                    #self.logger.info("self.bgp_header_end: %d", self.bgp_header_end)
                        
                        #bgpunfeasiblelen2 = bgpunfeasiblelen[1]
                                    #self.logger.info("BGP Unfeasible Routes Len: %s", bgpunfeasiblelen2[0])
                                    self.bgp_message_sum = self.bgp_message_sum + int(bgpunfeasiblelen2[0]) #Two is the unfeasible route len field length 
                                    
                                    if self.bgp_header_end+4+int(bgpunfeasiblelen2[0]) > len(packet):
                                        #self.logger.info("Packet size reached in total_path_att_len")
                                        #remaining_packet_size = len(packet) - self.bgp_header_end+4+int(bgpunfeasiblelen2[0])
                                        if len(packet) >= (self.bgp_header_end+2+int(bgpunfeasiblelen2[0])):  
                                            remaining_packet_size = len(packet) - (self.bgp_header_end+2+int(bgpunfeasiblelen2[0]))
                                        else:
                                            remaining_packet_size = (self.bgp_header_end+2+int(bgpunfeasiblelen2[0])) - len(packet)
                                        #self.logger.info("Remaining Packet size: %d", remaining_packet_size)
                                        self.remaining_buffer_type = 'update_header'
                                        if remaining_packet_size == 0:
                                            self.remaining_buffer = {}
                                        else:
                                            self.remaining_buffer = packet[self.bgp_header_end+2+int(bgpunfeasiblelen2[0]):self.bgp_header_end+2+int(bgpunfeasiblelen2[0])+remaining_packet_size]
                                        return
                        
                                    total_path_att_len = packet[self.bgp_header_end+2+int(bgpunfeasiblelen2[0]):self.bgp_header_end+4+int(bgpunfeasiblelen2[0])]
                                    totalpathattlen = unpack('!H',total_path_att_len)
                                    totalpathattlen1 = str(totalpathattlen).split('(')
                                    totalpathattlen2 = str(totalpathattlen1[1]).split(',')
                                    self.bgp_total_path_att_len = int(totalpathattlen2[0])
                                    #self.logger.info("BGP Total Path Attribute Length: %d", self.bgp_total_path_att_len)
                        
                                    self.total_path_attribute_len = 0
                                    self.bgp_header_end = self.bgp_header_end + 4
                                    if (int(totalpathattlen2[0])) > 0:
                                        #self.logger.info("self.buffer_next_packet: %d", self.buffer_next_packet)
                                        #self.logger.info("Packet future position: %d", int(totalpathattlen2[0]) + ((packet_total_len - self.bgp_length) + 19 + 4) + (self.buffer_next_packet + 4))
                                        #if int(totalpathattlen2[0]) + ((packet_total_len - self.bgp_length) + 19 + 4) + (self.buffer_next_packet + 4) > len(packet)-14:
                                        if (int(totalpathattlen2[0]) + (b+bgp_iterator - self.bgp_length + 19 + 4)) > len(packet):
                                            #self.logger.info("int(totalpathattlen2[0]) + (b+bgp_iterator + 19 + 4): %d", int(totalpathattlen2[0]) + (b+bgp_iterator + 19 + 4))
                                            #self.logger.info("len(packet: %d", len(packet))
                                            #self.logger.info("Packet size reached")
                                            #self.logger.info("packet_total_len: %d", packet_total_len)
                                        #remaining_packet_size = len(packet)-14 - int(totalpathattlen2[0])
                                            remaining_packet_size = len(packet) - (b+bgp_iterator - self.bgp_length + 19 + 4) #-- returned 0 in a test
                                             
                                            #remaining_packet_size = (b+bgp_iterator - self.bgp_length + 19 + 4 + int(totalpathattlen2[0])) - len(packet) 
                                            #remaining_packet_size = (len(packet)-14) - ((packet_total_len - self.bgp_length) + (19 + 4))
                                            #self.logger.info("Remaining Packet size: %d", remaining_packet_size)    
                                            #self.logger.info("bgp_iterator: %d", bgp_iterator)
                                            #self.logger.info("self.previous_buffer_len: %d", self.previous_buffer_len)
                                            #self.logger.info("Packet Range: From %d to %d", b+bgp_iterator-self.bgp_length+23,b+bgp_iterator-self.bgp_length+23+remaining_packet_size)
                                            packet_total_len = packet_total_len + remaining_packet_size
                                            updated_packet_total_len = 1
                                            
                                            #self.remaining_buffer = packet[b+bgp_iterator+19+4:b+bgp_iterator+19+4+remaining_packet_size]
                                            #self.remaining_buffer = packet[(packet_total_len-self.bgp_length)+(self.previous_buffer_len)+23:(packet_total_len-self.bgp_length)+(self.previous_buffer_len)+23+remaining_packet_size]
                                            if remaining_packet_size > 0:
                                                self.remaining_buffer = packet[b+bgp_iterator-self.bgp_length+23:b+bgp_iterator-self.bgp_length+23+remaining_packet_size]
                                            else:
                                                self.remaining_buffer = {}
                                            #self.remaining_buffer = packet[(len(packet)-14)-(19+4)-remaining_packet_size-1:len(packet)-14]
                                            #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer))
                                            self.buffer_next_packet = int(totalpathattlen2[0]) - len(self.remaining_buffer) 
                                            self.bgp_total_path_att_len = int(totalpathattlen2[0])
                                            self.bgp_type = 2
                                            self.remaining_buffer_type = 'attribute'
                                            #self.logger.info("Testing attributes in remaining buffer:")
                                            #path_att = self.remaining_buffer[0:3]
                                            #pathAtt = unpack('!BBB',path_att)
                                            #self.logger.info("remaining Attribute Type: %d", pathAtt[1])
                                            #self.logger.info("remaining Attribute Length: %d", pathAtt[2])
                                            return
                            
                            if self.remaining_buffer_type == 'unfeasible':
                                #self.logger.info("Formed BGP message from remaining update in unfeasible field.")
                                #self.logger.info("bgp_iterator: %d", bgp_iterator)
                                #self.logger.info("self.bgp_header_end: %d", self.bgp_header_end)
                                remaining_unfeasible = 2 - len(self.remaining_buffer)
                                #self.logger.info("len(self.remaining_buffer) == %d", len(self.remaining_buffer))
                                if len(self.remaining_buffer) == 0:                                    
                                    bgp_unfeasible_routes_len = packet[b:b+remaining_unfeasible]
                                else:
                                    bgp_unfeasible_routes_len = self.remaining_buffer + packet[b:b+remaining_unfeasible]
                                #total_path_att_len = packet[b:b+2]
                                bgpunfeasiblelen = unpack('!H',bgp_unfeasible_routes_len)
                                bgpunfeasiblelen1 = str(bgpunfeasiblelen).split('(')
                                bgpunfeasiblelen2 = str(bgpunfeasiblelen1[1]).split(',')
                                #self.logger.info("self.bgp_header_end: %d", self.bgp_header_end)                    
                                #self.logger.info("BGP Unfeasible Routes Len: %s", bgpunfeasiblelen2[0])
                                self.bgp_message_sum = self.bgp_message_sum + int(bgpunfeasiblelen2[0])
                                
                                total_path_att_len = packet[b+remaining_unfeasible:b+remaining_unfeasible+2]
                                totalpathattlen = unpack('!H',total_path_att_len)
                                totalpathattlen1 = str(totalpathattlen).split('(')
                                totalpathattlen2 = str(totalpathattlen1[1]).split(',')
                                self.bgp_total_path_att_len = int(totalpathattlen2[0])
                                self.total_path_attribute_len = 0
                                #self.logger.info("BGP Total Path Attribute Length: %d", self.bgp_total_path_att_len)
                                if len(self.remaining_buffer) == 0:
                                    self.path_attributes = packet[b+4:b+4+self.bgp_total_path_att_len] # b+2+2 == b+(len(Unfeasible Routes Len) + len(Total Path Attribute Len))
                                    self.bgp_header_end = b+4
                                else:
                                    self.path_attributes = packet[b+3:b+3+self.bgp_total_path_att_len] # b+1+2 == b+(len(Unfeasible Routes Len) + len(Total Path Attribute Len))
                                    self.bgp_header_end = b+3
                                    self.previous_buffer_len = len(self.remaining_buffer)
                                    self.remaining_buffer = {}
                                add_nlri_to_bgp_iterator = 1
                                type_unfeasible_len_before_buffer_len_zero = 1
                                #self.bgp_header_end = b+2+self.bgp_total_path_att_len
                                #self.bgp_header_end = b+4
                                        
                            if self.remaining_buffer_type == 'update_header':            
                                #self.logger.info("Formed BGP message from remaining update header of previous packet.")
                                #self.logger.info("bgp_iterator: %d", bgp_iterator)
                                #self.logger.info("self.bgp_header_end: %d", self.bgp_header_end)
                                
                                if len(self.remaining_buffer) == 0:
                                    #self.logger.info("len(self.remaining_buffer) == 0")
                                    total_path_att_len = packet[b:b+2] #add remaining_buffer
                                else:
                                    #self.logger.info("len(self.remaining_buffer) == %d",len(self.remaining_buffer))
                                    total_path_att_len = self.remaining_buffer + packet[b:b+(2-len(self.remaining_buffer))]
                                totalpathattlen = unpack('!H',total_path_att_len)
                                totalpathattlen1 = str(totalpathattlen).split('(')
                                totalpathattlen2 = str(totalpathattlen1[1]).split(',')
                                self.bgp_total_path_att_len = int(totalpathattlen2[0])
                                self.total_path_attribute_len = 0
                                #self.logger.info("BGP Total Path Attribute Length: %d", self.bgp_total_path_att_len)
                                if len(self.remaining_buffer) == 0:
                                    self.path_attributes = packet[b+2:b+2+self.bgp_total_path_att_len]
                                else:
                                    self.path_attributes = packet[b+(2-len(self.remaining_buffer)):b+(2-len(self.remaining_buffer))+self.bgp_total_path_att_len]
                                #self.bgp_header_end = b+2+self.bgp_total_path_att_len
                                self.bgp_header_end = b+(2-len(self.remaining_buffer))
                                #self.logger.info("Set `self.previous_buffer_len` to a non-zero value")  
                                self.previous_buffer_len = self.bgp_total_path_att_len
                                        
                            if self.remaining_buffer_type == 'attribute':
                                if self.remaining_buffer == {}:
                                    self.path_attributes = packet[b:b+self.buffer_next_packet]
                                    bgp_iterator = bgp_iterator + len(self.path_attributes)
                                    add_nlri_to_bgp_iterator = 1
                                    self.bgp_header_end = b
                                    #self.logger.info("self.bgp_header_end = b")
                                else:    
                                    self.path_attributes = self.remaining_buffer + packet[b:b+self.buffer_next_packet]
                                    #self.logger.info("self.buffer_next_packet: %d", self.buffer_next_packet)
                                    self.bgp_header_end = b + bgp_iterator - len(self.remaining_buffer)
                                #new_packet = self.remaining_buffer + packet
                                #self.bgp_header_end = b + bgp_iterator - len(self.remaining_buffer)                          
                                #packet_header = packet[0:b]
                                #packet_data = packet[b+self.buffer_next_packet:len(packet)] #take packet data
                                #packet = packet_header + packet_data
                                #self.logger.info("Formed BGP message from remaining attributes of previous packet.")
                                #self.logger.info("bgp_iterator: %d", bgp_iterator)
                                #self.logger.info("self.bgp_header_end: %d", self.bgp_header_end)
                                self.previous_buffer_len = len(self.remaining_buffer)
                                #bgp_iterator = bgp_iterator + len(self.remaining_buffer)
                                self.remaining_buffer = {}
                                #self.remaining_buffer_type = {}
                                #self.logger.info("len(self.remaining_buffer)== %d",len(self.remaining_buffer))                
                                #self.bgp_header_end = 0
                                
                    
                                #self.logger.info("self.path_attributes length: %d",len(self.path_attributes))
                                
                                
                                #self.logger.info("Testing attributes:")
                                #self.logger.info("First part:")
                                path_att = self.path_attributes[0:3]
                                pathAtt = unpack('!BBB',path_att)
                                #self.logger.info("Attribute Type: %d", pathAtt[1])
                                #self.logger.info("Attribute Length: %d", pathAtt[2])
                                
                                #self.logger.info("Second part:")
                                #path_att = self.path_attributes[b:b+3]
                                #pathAtt = unpack('!BBB',path_att)
                                #self.logger.info("Attribute Type: %d", pathAtt[1])
                                #self.logger.info("Attribute Length: %d", pathAtt[2])                                
                                
                            if self.bgp_type != 1 and self.bgp_type != 3 and self.bgp_type != 4:  
                                list_communities_extended_len_flags = [16,48,80,144,112,176,208,240]   
                                #self.logger.info("self.bgp_message_sum: %d", self.bgp_message_sum)       
                                self.bgp_message_sum = self.bgp_message_sum + self.bgp_total_path_att_len                                
                                #if len(self.path_attributes) == 0:
                                if self.remaining_buffer_type != 'attribute' and self.remaining_buffer_type != 'update_header' and self.remaining_buffer_type != 'unfeasible':
                                    #self.logger.info("len(self.path_attributes) == 0")
                                    #self.logger.info("len(self.remaining_buffer)== %d",len(self.remaining_buffer))
                                    #self.logger.info("Will change path attributes")
                                    self.path_attributes = packet[self.bgp_header_end:self.bgp_header_end + self.bgp_total_path_att_len]
                                else:
                                    #self.logger.info("self.remaining_buffer_type <- {}")
                                    self.remaining_buffer_type = {}
                                    self.remaining_buffer = {}
                            #self.total_path_attribute_len = 0
                                #self.logger.info("self.path_attributes length: %d",len(self.path_attributes))
                                if len(self.path_attributes) < self.bgp_total_path_att_len:
                                    #self.logger.info("len(self.path_attributes): %d < self.bgp_total_path_att_len: %d",len(self.path_attributes),self.bgp_total_path_att_len)
                                    self.remaining_buffer_type = 'attribute'
                                    self.remaining_buffer = self.path_attributes
                                    #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer))
                                while self.total_path_attribute_len < self.bgp_total_path_att_len:
                                    #self.logger.info("------------------------------------------")
                                    #self.logger.info("self.total_path_attribute_len: %d", self.total_path_attribute_len)
                                    path_att = self.path_attributes[self.total_path_attribute_len:self.total_path_attribute_len+3]
                                    pathAtt = unpack('!BBB',path_att)                                    
                                    #self.logger.info("Attribute Type: %d", pathAtt[1])
                                    #if pathAtt[1] <= 8:
                                    #   self.logger.info("Attribute Length: %d", pathAtt[2])
                                    if pathAtt[1] == 1:
                                        #self.logger.info("Attribute: ORIGIN") #The ORIGIN code tells how BGP learned about he specif route
                                        attribute_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                        attributeValue = unpack('!B',attribute_value)                            
                                        attributeValue1 = str(attributeValue).split('(')
                                        attributeValue2 = str(attributeValue1[1]).split(',')
                                        #if int(attributeValue2[0]) == 0:
                                        #    self.logger.info("ORIGIN Value: 0-IGP")
                                        #elif int(attributeValue2[0]) == 1:
                                        #    self.logger.info("ORIGIN Value: 1-EGP")
                                        #elif int(attributeValue2[0]) == 2:
                                        #    self.logger.info("ORIGIN Value: 2-INCOMPLETE")
                                    if pathAtt[1] == 2:
                                        #self.logger.info("Attribute: AS_PATH")                                   
                                        attribute_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+4]
                                        attributeValue = unpack('!B',attribute_value)                                       
                                        attributeValue1 = str(attributeValue).split('(')
                                        attributeValue2 = str(attributeValue1[1]).split(',')
                                        #if int(attributeValue2[0]) == 1:
                                        #    self.logger.info("AS_PATH Segment Type: 1-AS_SET")
                                        #elif int(attributeValue2[0]) == 2:
                                        #    self.logger.info("AS_PATH Segment Type: 2-AS_SEQUENCE") 
                                        #Segment Length:      
                                        attribute_value = self.path_attributes[self.total_path_attribute_len+4:self.total_path_attribute_len+5]
                                        attributeValue = unpack('!B',attribute_value)                                       
                                        attributeValue1 = str(attributeValue).split('(')
                                        attributeValue2 = str(attributeValue1[1]).split(',') 
                                        #self.logger.info("AS_PATH Segment Length: %d", int(attributeValue2[0]))
                                        num_ASes = 0
                                        cont = 0
                                        while num_ASes < int(attributeValue2[0]):
                                            as_sequence_value = self.path_attributes[self.total_path_attribute_len+5+cont:self.total_path_attribute_len+9+cont]
                                            as_sequenceValue = unpack('!I',as_sequence_value)                                       
                                            as_sequenceValue1 = str(as_sequenceValue).split('(')
                                            as_sequenceValue2 = str(as_sequenceValue1[1]).split(',') 
                                            #self.logger.info("AS: %d", int(as_sequenceValue2[0]))
					    self.as_path_list_str = self.as_path_list_str + str(int(as_sequenceValue2[0])) + " "
                                            num_ASes = num_ASes + 1 
                                            cont = cont + 4 #Each AS has 4 Bytes                      
                                    if pathAtt[1] == 3:
                                        #self.logger.info("Attribute: NEXT_HOP")
                                        attribute_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                        #self.logger.info("Length attribute_value: %d", len(attribute_value))
                                        attributeValue = unpack('!4s',attribute_value)
                                        next_hop = socket.inet_ntoa(attribute_value)                                    
                                        #self.logger.info("NEXT_HOP Value: %s", next_hop)
                                    #self.logger.info("NEXT_HOP Value: %s", attributeValue2[0])
                                    if pathAtt[1] == 4:
                                        #self.logger.info("Attribute: MULTI-EXIT DISCRIMINATOR (MED)")
                                        med_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                        med = unpack('!I',med_value)
                                        med1 = str(med).split('(')
                                        med2 = str(med1[1]).split(',') 
                                        #self.logger.info("MED Value: %d", int(med2[0]))
                                    if pathAtt[1] == 5:
                                        #self.logger.info("Attribute: LOCAL_PREFERENCE")
                                        local_pref_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                        local_pref = unpack('!I',local_pref_value)
                                        locpref1 = str(local_pref).split('(')
                                        locpref2 = str(locpref1[1]).split(',') 
                                        #self.logger.info("Local Preference Value: %d", int(locpref2[0]))                                    
                                    if pathAtt[1] == 6:
                                        #self.logger.info("Attribute: ATOMIC_AGGREGATE")
                                        if pathAtt[2] > 0:
                                            atomic_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                            atomic_aggregate = unpack('!B',local_pref_value)
                                            atomic1 = str(atomic_aggregate).split('(')
                                            atomic2 = str(atomic1[1]).split(',') 
                                            #self.logger.info("Atomic Aggregate Value: %d", int(atomic2[0]))                                    
                                    if pathAtt[1] == 7:
                                        #self.logger.info("Attribute: AGGREGATOR")
                                        if pathAtt[2] > 0:
                                            aggregator_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                            aggregator = unpack('!I4s',aggregator_value)
                                            aggregator_as = aggregator[0]
                                            #self.logger.info("Aggregator AS: %s", str(aggregator_as))
                                            aggregator_origin = aggregator[1]
                                            aggregatorOrigin = socket.inet_ntoa(aggregator_origin)
                                            #self.logger.info("Aggregator Origin:  %s", str(aggregatorOrigin))
                                    if pathAtt[1] == 8:
                                        #self.logger.info("Attribute: COMMUNITIES")                                        
                                        #self.logger.info("Attribute Flags value: %d", pathAtt[0]) #Flags == 192 means regular community (len = 8)
                                        if pathAtt[0] in list_communities_extended_len_flags:
                                            #self.logger.info("pathAtt[0] > 192: Extended Length.")
                                            path_att = self.path_attributes[self.total_path_attribute_len:self.total_path_attribute_len+4]
                                            pathAtt = unpack('!BBH',path_att)
                                            #self.logger.info("Attribute Length: %d", pathAtt[2])
                                            self.total_path_attribute_len = self.total_path_attribute_len+4+pathAtt[2]
                                        else:
                                            if pathAtt[2] == 4:
                                                community_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                                community = unpack('!HH',community_value)
                                                community_as = community[0]
                                                #self.logger.info(" AS: %s", str(aggregator_as))
                                                community_value = community[1]
                                        #aggregatorOrigin = socket.inet_ntoa(aggregator_origin)
                                                #self.logger.info("Community:  %s:%s", str(community_as), str(community_value))
                                            elif pathAtt[2] == 8:
                                                community_value = self.path_attributes[self.total_path_attribute_len+3:self.total_path_attribute_len+3+pathAtt[2]]
                                                community = unpack('!HHHH',community_value)
                                                community_as = community[0]                                        #
                                                community_value = community[1]                                        
                                                #self.logger.info("Community:  %s:%s", str(community_as), str(community_value))
                                                community_as2 = community[2]                                        
                                                community_value2 = community[3]                                        
                                                #self.logger.info("Community:  %s:%s", str(community_as2), str(community_value2))
                                    if pathAtt[1] == 16:
                                        #self.logger.info("Attribute: EXTENDED_COMMUNITIES")
                                        #self.logger.info("Attribute Flags value: %d", pathAtt[0]) #Flags == 192 means regular community (len = 8)
                                        if pathAtt[0] in list_communities_extended_len_flags:
                                            path_att = self.path_attributes[self.total_path_attribute_len:self.total_path_attribute_len+4]
                                            pathAtt = unpack('!BBH',path_att)
                                            #self.logger.info("Attribute Length: %d", pathAtt[2])
                                            self.total_path_attribute_len = self.total_path_attribute_len+4+pathAtt[2]
                                        #else:
                                        #    self.logger.info("Attribute Length: %d", pathAtt[2])                                                                      
                                        #    self.total_path_attribute_len = self.total_path_attribute_len+3+pathAtt[2]
                                    if pathAtt[0] not in list_communities_extended_len_flags:
                                        #self.logger.info("pathAtt[1] != 16 or pathAtt[0] <= 192")
                                        #self.logger.info("Attribute Length: %d", pathAtt[2])                                                                      
                                        self.total_path_attribute_len = self.total_path_attribute_len+3+pathAtt[2]                                
                            #self.logger.info("------------------------------------------")  
                        #nlri_value = packet[self.bgp_header_end+self.bgp_length-4:self.bgp_header_end+self.bgp_length]
                        
                        if self.bgp_type == 4:
                            self.logger.info("BGP Type: 4-KEEPALIVE")
                            #bgp_iterator = bgp_iterator + 19    
                            #self.logger.info("bgp_iterator: %d",bgp_iterator)                         
                        
                        if (self.remaining_buffer == {} and self.bgp_type != 1) or self.remaining_buffer_type == 'nlri':
                                if self.total_path_attribute_len > 0 or self.remaining_buffer_type == 'nlri':
                                    #self.logger.info("BGP message len: %d",self.bgp_length)
                            #self.logger.info("BGP self.bgp_message_sum: %d",self.bgp_message_sum)
                                    nlri_counter = 0
                                    self.bgp_message_sum = self.bgp_message_sum + 4 #verify why bgp_message_sum has 4 bytes less than desired
                                    #self.logger.info("BGP self.bgp_message_sum: %d",self.bgp_message_sum)

                                    if self.remaining_buffer_type == 'nlri':
                                        #self.logger.info("Formed BGP message from remaining nlri of previous packet.")
                                        self.total_path_attribute_len = 0
                                        add_nlri_to_bgp_iterator = 1
                                        if len(self.remaining_buffer) == 0:
                                            nlri_value = packet[b:b+1]
                                            #self.logger.info("nlri_value = packet[b:b+1]")
                                        else:
                                            nlri_value = self.remaining_buffer[0]
                                            #self.logger.info("nlri_value = self.remaining_buffer[0]")
                                            if len(self.remaining_buffer) > 5:
                                                new_packet = packet[0:b] + self.remaining_buffer + packet[b:len(packet)]
                                                packet = new_packet
                                                self.remaining_buffer = {}
                                                
                                        nlriValue = unpack('!B',nlri_value)
                                        nlriValue1 = str(nlriValue).split('(')
                                        nlriValue2 = str(nlriValue1[1]).split(',')
                                        #self.logger.info("nlri value length: %d",int(nlriValue2[0]))
                                      
                                        if int(nlriValue2[0]) >= 17 and int(nlriValue2[0]) <= 24:
                                            packet_len = 4 - len(self.remaining_buffer)
                                        elif int(nlriValue2[0]) >=9 and int(nlriValue2[0]) <= 16:
                                            packet_len = 3 - len(self.remaining_buffer)
                                        elif int(nlriValue2[0]) <= 8:
                                            packet_len = 2 - len(self.remaining_buffer)
                                        elif int(nlriValue2[0]) >=25:
                                            packet_len = 5 - len(self.remaining_buffer)
                                        #if len(self.remaining_buffer) == 0:
                                            
                                            #if int(nlriValue2[0]) >= 17 and int(nlriValue2[0]) <= 24:
                                            #    packet_len = 4
                                            #elif int(nlriValue2[0]) <= 16:
                                            #    packet_len = 3
                                            #elif int(nlriValue2[0]) >=25:
                                            #    packet_len = 5
                                        #else:
                                            #packet_len = 4 - len(self.remaining_buffer)
                                            
                                        #self.logger.info("packet_len: %d",packet_len)
                                        if packet_len == 2 and len(self.remaining_buffer) == 0: 
                                            new_packet = self.remaining_buffer + packet[b:b+packet_len+2]
                                            #self.logger.info("packet_len == 3 and len(self.remaining_buffer) == 0")
                                        elif packet_len == 3 and len(self.remaining_buffer) == 0: 
                                            new_packet = self.remaining_buffer + packet[b:b+packet_len+1]
                                            #self.logger.info("packet_len == 3 and len(self.remaining_buffer) == 0")
                                        elif packet_len == 5 and len(self.remaining_buffer) == 0: 
                                            new_packet = self.remaining_buffer + packet[b:b+packet_len-1] 
                                            self.bgp_message_sum = self.bgp_message_sum + 1
                                            #self.logger.info("packet_len == 5 and len(self.remaining_buffer) == 0")
                                        else:
                                            if (len(self.remaining_buffer) + packet_len) == 4:
                                                new_packet = self.remaining_buffer + packet[b:b+packet_len]
                                            elif (len(self.remaining_buffer) + packet_len) == 3:
                                                new_packet = self.remaining_buffer + packet[b:b+packet_len+1]
                                            elif (len(self.remaining_buffer) + packet_len) == 2:
                                                new_packet = self.remaining_buffer + packet[b:b+packet_len+2]
                                            elif (len(self.remaining_buffer) + packet_len) == 5:
                                                new_packet = self.remaining_buffer + packet[b:b+packet_len-1] 
                                                self.bgp_message_sum = self.bgp_message_sum + 1
                                                #self.logger.info("BGP self.bgp_message_sum incremented to: %d",self.bgp_message_sum)
                                        #new_packet = self.remaining_buffer + packet[b:b+4]
                                        nlriValue = unpack('!4s',new_packet)
                                        nlri = socket.inet_ntoa(new_packet)
                                        nlri_split = str(nlri).split('.')
                                        if int(nlri_split[0]) >= 17 and int(nlri_split[0]) <= 24:
                                            self.logger.info("NLRI: %s.%s.%s.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0]))
                                            nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0])
                                            self.total_number_prefixes = self.total_number_prefixes + 1 
                                            #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                            self.accepted_prefixes_set.add(nlri_str)
                                            self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                            #self.logger.info("NLRI STRING >=17 and <=24: %s",nlri_str)
                                        elif int(nlri_split[0]) <= 8:
                                            self.logger.info("NLRI: %s.0.0.0/%s", str(nlri_split[1]),str(nlri_split[0]))
                                            nlri_str = str(nlri_split[1])+".0.0.0/"+str(nlri_split[0])
                                            self.total_number_prefixes = self.total_number_prefixes + 1 
                                            #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                            self.accepted_prefixes_set.add(nlri_str)
                                            self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                            #self.logger.info("NLRI STRING <16: %s",nlri_str)
                                        elif int(nlri_split[0]) >= 9 and int(nlri_split[0]) <= 16:
                                            self.logger.info("NLRI: %s.%s.0.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[0]))
                                            nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+".0.0/"+str(nlri_split[0])
                                            self.total_number_prefixes = self.total_number_prefixes + 1 
                                            #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                            self.accepted_prefixes_set.add(nlri_str)
                                            self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                            #self.logger.info("NLRI STRING <16: %s",nlri_str)
                                        elif int(nlri_split[0]) > 24:
                                            if len(self.remaining_buffer) > 0:
                                                new_packet_len5 = self.remaining_buffer[1:len(self.remaining_buffer)] + packet[b:b+packet_len] #Take 4 bytes except from prefix len
                                            else:
                                                new_packet_len5 = packet[b+1:b+packet_len]
                                                #new_packet_len5 = self.remaining_buffer + packet[b+1:b+packet_len] #Take 4 bytes except from prefix len
                                            nlriValue_len5 = unpack('!4s',new_packet_len5)
                                            nlri_len5 = socket.inet_ntoa(new_packet_len5)
                                            nlri_split_len5 = str(nlri_len5).split('.')
                                            self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split_len5[0]),str(nlri_split_len5[1]),str(nlri_split_len5[2]),str(nlri_split_len5[3]),str(nlri_split[0]))
                                            nlri_str = str(nlri_split_len5[0])+"."+str(nlri_split_len5[1])+"."+str(nlri_split_len5[2])+"."+str(nlri_split_len5[3])+"/"+str(nlri_split[0])
                                            self.total_number_prefixes = self.total_number_prefixes + 1 
                                            #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                            self.accepted_prefixes_set.add(nlri_str)
                                            self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                         
                                            #self.logger.info("NLRI STRING > 24: %s",nlri_str)
                                        self.total_number_prefixes = self.total_number_prefixes + 1 
                                        #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                                    
                                        #packet_header = packet[0:b]                                
                                        #packet_data = packet[b+packet_len:len(packet)] #take packet data
                                        #packet = packet_header + packet_data
                                        #if has_buffer_from_previous_packet == 1:
                                        bgp_iterator = packet_len
                                        #self.logger.info("bgp_iterator = packet_len: %d",bgp_iterator)
                                        #else: 
                                        #    bgp_iterator = 0   
                                        #    self.logger.info("bgp_iterator = 0") 
                                        self.bgp_header_end = b + bgp_iterator                                    
                                        #self.bgp_header_end = b + bgp_iterator - len(self.remaining_buffer)
                                        self.remaining_buffer_type = {}
                                        self.remaining_buffer = {} 
                                        #self.bgp_header_end = b + bgp_iterator
                                        #self.logger.info("bgp_iterator: %d",bgp_iterator)
                                        #self.logger.info("self.bgp_header_end: %d",self.bgp_header_end)
                                        #self.logger.info("len(packet): %d",len(packet))
                                        #self.logger.info("total_len: %d",total_len)
                                        self.previous_buffer_len = 0
                            
                                    while self.bgp_message_sum < self.bgp_length and self.bgp_type != 1:
                                        #self.logger.info("BGP self.bgp_message_sum: %d",self.bgp_message_sum)
                                        #self.logger.info("NLRI starts at: %d",self.bgp_header_end+self.total_path_attribute_len+nlri_counter)
                                        #self.logger.info("NLRI self.total_path_attribute_len: %d",self.total_path_attribute_len)
                                        #self.logger.info("NLRI nlri_counter: %d",nlri_counter)
                                        #self.logger.info("NLRI self.bgp_header_end: %d",self.bgp_header_end)
                                        nlriValueLen2 = 0
                                        nlriValueLen3 = 0
                                        nlriValueValue25 = 0
                                        nlriValueValue26 = 0
                                        nlriValueValue27 = 0
                                        nlriValueValue28 = 0
                                        nlriValueValue32 = 0
                                        nlri_len = 0
                                        if self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1 == len(packet):
                                            nlri_value = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1]
                                            nlriValue = unpack('!B',nlri_value)
                                            nlriValue1 = str(nlriValue).split('(')
                                            nlriValue2 = str(nlriValue1[1]).split(',')
                                            #self.logger.info("nlri value: %d",int(nlriValue2[0]))   
                                            if int(nlriValue2[0]) <= 8: #prefix of type X.X.0.0
                                                nlriValueLen2 = 1
                                                #self.logger.info("int(nlriValue2[0]) < 17")
                                                nlri_len = 2                                         
                                            if int(nlriValue2[0]) >= 9 and int(nlriValue2[0]) < 17: #prefix of type X.X.0.0
                                                nlriValueLen3 = 1
                                                #self.logger.info("int(nlriValue2[0]) < 17")
                                                nlri_len = 3
                                            elif int(nlriValue2[0]) >=17 and int(nlriValue2[0]) <=24:
                                                #self.logger.info("int(nlriValue2[0]) == 24")
                                                nlri_len = 4
                                            elif int(nlriValue2[0]) == 25: #prefix of type X.X.X.0
                                                nlriValueValue25 = 1
                                                #self.logger.info("int(nlriValue2[0]) == 25")
                                                nlri_len = 5
                                            elif int(nlriValue2[0]) == 26: #prefix of type X.X.X.0
                                                nlriValueValue26 = 1
                                                #self.logger.info("int(nlriValue2[0]) == 25")
                                                nlri_len = 5
                                            elif int(nlriValue2[0]) == 27: #prefix of type X.X.X.0
                                                nlriValueValue27 = 1
                                                #self.logger.info("int(nlriValue2[0]) == 25")
                                                nlri_len = 5
                                            elif int(nlriValue2[0]) == 28: #prefix of type X.X.X.0
                                                nlriValueValue28 = 1
                                                #self.logger.info("int(nlriValue2[0]) == 28")
                                                nlri_len = 5
                                            elif int(nlriValue2[0]) > 28 and int(nlriValue2[0]) <= 32:
                                                nlriValueValue32 = 1
                                                #self.logger.info("int(nlriValue2[0]) > 28 and int(nlriValue2[0]) <= 32")
                                                nlri_len = 5
                                            if int(nlriValue2[0]) == 0:
                                                return
                                        if self.bgp_header_end+self.total_path_attribute_len+nlri_counter+nlri_len >= len(packet):
                                            #self.logger.info("Packet size reached")
                                            self.remaining_buffer_type = 'nlri'
                                        #remaining_packet_size = total_len - len(packet)
                                        #remaining_packet_size = (self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4) - len(packet)
                                            remaining_packet_size = len(packet) - (self.bgp_header_end+self.total_path_attribute_len+nlri_counter)
                                            #self.logger.info("Remaining Packet size: %d", remaining_packet_size)
                                          
                                            self.remaining_buffer = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+remaining_packet_size]
                                            #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer))
                                            self.total_path_attribute_len = 0
                                            return
                                        nlri_value = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1]
                                        nlriValue = unpack('!B',nlri_value)
                                        nlriValue1 = str(nlriValue).split('(')
                                        nlriValue2 = str(nlriValue1[1]).split(',')
                                        #self.logger.info("nlri value: %d",int(nlriValue2[0]))
                                        
                                        if int(nlriValue2[0]) <= 8: #prefix of type X.X.0.0
                                            nlriValueLen2 = 1
                                            #self.logger.info("int(nlriValue2[0]) <= 8")
                                        if int(nlriValue2[0]) >= 9 and int(nlriValue2[0]) < 17: #prefix of type X.X.0.0
                                            nlriValueLen3 = 1
                                            #self.logger.info("int(nlriValue2[0]) >= 9 and int(nlriValue2[0]) < 17")
                                        elif int(nlriValue2[0]) == 25: #prefix of type X.X.0.0
                                            nlriValueValue25 = 1
                                            #self.logger.info("int(nlriValue2[0]) == 25")
                                        elif int(nlriValue2[0]) == 26: #prefix of type X.X.0.0
                                            nlriValueValue26 = 1
                                            #self.logger.info("int(nlriValue2[0]) == 26")
                                        elif int(nlriValue2[0]) == 27: #prefix of type X.X.0.0
                                            nlriValueValue27 = 1
                                            #self.logger.info("int(nlriValue2[0]) == 27")
                                        elif int(nlriValue2[0]) == 28: #prefix of type X.X.0.0
                                            nlriValueValue28 = 1
                                            #self.logger.info("int(nlriValue2[0]) == 28")
                                        elif int(nlriValue2[0]) > 28 and int(nlriValue2[0]) <= 32:
                                            nlriValueValue32 = 1
                                            #self.logger.info("int(nlriValue2[0]) > 28 and int(nlriValue2[0]) <= 32")
                                        nlri_zero = 0
                                        if int(nlriValue2[0]) == 0:
                                            self.logger.info("NLRI: 0.0.0.0/0")
                                            nlri_str = "0.0.0.0/0"
                                            self.accepted_prefixes_set.add(nlri_str)
                                            self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                            nlri_zero = 1
                                            if self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5 > len(packet):
                                                #self.logger.info("Packet size reached")
                                                self.remaining_buffer_type = 'nlri'
                                        #remaining_packet_size = total_len - len(packet)
                                        #remaining_packet_size = (self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5) - len(packet)
                                                remaining_packet_size = len(packet) - (self.bgp_header_end+self.total_path_attribute_len+nlri_counter) 
                                                #self.logger.info("Remaining Packet size: %d", remaining_packet_size)
                                    
                                                self.remaining_buffer = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+remaining_packet_size]
                                                #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer))
                                                return     
                                            nlri_value = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5]
                                            self.bgp_message_sum = self.bgp_message_sum + 5
                                        else:          
                                            if self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4 > len(packet):
                                                #self.logger.info("Packet size reached")
                                                self.remaining_buffer_type = 'nlri'
                                        #remaining_packet_size = total_len - len(packet)
                                        #remaining_packet_size = (self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4) - len(packet)
                                                remaining_packet_size = len(packet) - (self.bgp_header_end+self.total_path_attribute_len+nlri_counter)
                                                #self.logger.info("Remaining Packet size: %d", remaining_packet_size)
                                          
                                                self.remaining_buffer = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+remaining_packet_size]
                                                #self.logger.info("remaining_buffer length after: %d", len(self.remaining_buffer))
                                                return   
                                            if int(nlriValue2[0]) <= 24:      
                                                nlri_value = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4]
                                                #self.logger.info("int(nlriValue2[0]) <= 24")
                                            elif int(nlriValue2[0]) > 24:    
                                                self.logger.info("self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1: %d",self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1) 
                                                self.logger.info("self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5: %d",self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5) 
                                                nlri_value = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter+1:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5]
                                                self.logger.info("int(nlriValue2[0]) > 24")
                                                #self.bgp_message_sum = self.bgp_message_sum + 4
                                        if self.bgp_type != 1:
					    current_time = datetime.now().strftime("%H:%M:%S")
					    current_time_list = current_time.split(":")
					    hours = int(current_time_list[0])*3600
					    minutes = int(current_time_list[1])*60
					    timestamp = hours + minutes + int(current_time_list[2])
					    if len(self.accepted_prefixes_set) >= 746400:
					    	if self.start_time == 0:
							self.start_time = timestamp
						self.logger.info("elapsed time: %s", str(timestamp-self.start_time))
						if timestamp-self.start_time >= 200:
							if self.send_announcement == 0:
								msg = "neighbor 100.78.128.1 announce route 184.164.227.0/24 next-hop self origin egp"
            							self.sendMessage(msg)
								self.send_announcement = 1
                                            if int(nlriValue2[0]) <= 24:
                                                #self.logger.info("Remaining BGP Message: %d", self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4)
                                                nlriValue = unpack('!4s',nlri_value)
                                                nlri = socket.inet_ntoa(nlri_value)
                                                nlri_split = str(nlri).split('.')
                                            elif int(nlriValue2[0]) > 24:
                                                self.logger.info("Remaining BGP Message: %d", self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5)
                                                self.logger.info("Len nlri_value: %d",len(nlri_value))
                                                nlriValue = unpack('!4s',nlri_value)
                                                nlri = socket.inet_ntoa(nlri_value)
                                                nlri_split = str(nlri).split('.')
                                            #test if the next byte == FF in Hexa, besides the current byte in nlri_split[3]
                                            nlriNextByte = ""
                                            if self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5 <= len(packet):
                                                nlri_next_byte = packet[self.bgp_header_end+self.total_path_attribute_len+nlri_counter+4:self.bgp_header_end+self.total_path_attribute_len+nlri_counter+5]
                                                nlriNextByte = unpack('!s',nlri_next_byte)
                                                #nlriNextByte1 = nlriNextByte.split('(')
                                                #nlriNextByte2 = nlriNextByte1[1].split(',')
                                                #self.logger.info("nlri value: %d",int(nlriValue2[0]))
                                                #self.logger.info("nlriNextByte == %s",nlriNextByte)
                                                #self.logger.info("nlriNextByte[0] == %s",nlri_next_byte[0])
                                            if str(nlri_split[3]) == "255" and nlriNextByte == "('\xff',)" and nlriValueLen3 == 1:
                                                #self.logger.info("str(nlri_split[3]) == %s",str(nlri_split[3]))
                                                self.logger.info("NLRI: %s.%s.0.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[0]))
                                                nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+".0.0/"+str(nlri_split[0])                                                
                                                nlri_counter = nlri_counter + 3 + nlri_zero
                                                self.bgp_message_sum = self.bgp_message_sum + 3
                                                self.total_number_prefixes = self.total_number_prefixes + 1 
                                                #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                self.accepted_prefixes_set.add(nlri_str)
						if nlri_str == "184.164.226.0/24":
							current_time = datetime.now().strftime("%H:%M:%S")
							to_print = self.as_path_list_str + "\n" + current_time
							f = open('/home/ubuntu/update_file.txt','a')
	    						f.write(to_print)
							f.write('\n')
	    						f.close() 
                                                self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                #self.logger.info("------------------------------------------")
                                            else:
                                                if nlriValueLen3 == 1:
                                                    #self.logger.info("nlriValueLen3 == 1")
                                                    self.logger.info("NLRI: %s.%s.0.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[0]))
                                                    nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+".0.0/"+str(nlri_split[0])  
                                                    nlri_counter = nlri_counter + 3 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 3 
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
						    if nlri_str == "184.164.226.0/24":
							current_time = datetime.now().strftime("%H:%M:%S")
							to_print = self.as_path_list_str + "\n" + current_time
							f = open('/home/ubuntu/update_file.txt','a')
	    						f.write(to_print)
							f.write('\n')
	    						f.close()
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set)) 
                                                    #self.logger.info("------------------------------------------")
                                                elif nlriValueLen2 == 1:
                                                    #self.logger.info("nlriValueLen2 == 1")
                                                    #self.logger.info("NLRI: %s.0.0.0/%s", str(nlri_split[1]),str(nlri_split[0]))
                                                    nlri_str = str(nlri_split[1])+".0.0.0/"+str(nlri_split[0])  
                                                    nlri_counter = nlri_counter + 2 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 2 
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
						    if nlri_str == "184.164.226.0/24":
							current_time = datetime.now().strftime("%H:%M:%S")
							to_print = self.as_path_list_str + "\n" + current_time
							f = open('/home/ubuntu/update_file.txt','a')
	    						f.write(to_print)
							f.write('\n')
	    						f.close()
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set)) 
                                                    #self.logger.info("------------------------------------------")
                                                elif nlriValueValue25 == 1: #prefix of type X.X.0.0
                                                    #self.logger.info("nlriValueValue25 == 1")
                                                    #self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split[0]),str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlriValue2[0])) 
                                                    nlri_str = str(nlri_split[0])+"."+str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+"/"+str(nlriValue2[0])
                                                    #self.logger.info("NLRI STRING > 24: %s",nlri_str)
                                                    #nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+".0.128/"+str(nlri_split[0])                                                      
                                                    nlri_counter = nlri_counter + 5 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 5 
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                    #self.logger.info("------------------------------------------")
                                                elif nlriValueValue26 == 1: #prefix of type X.X.0.0
                                                    #self.logger.info("nlriValueValue26 == 1")
                                                    #self.logger.info("NLRI: %s.%s.%s.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0])) 
                                                    #nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0]) 
                                                    #self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split[0]),str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlriValue2[0])) 
                                                    nlri_str = str(nlri_split[0])+"."+str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+"/"+str(nlriValue2[0])
                                                    #self.logger.info("NLRI STRING > 24: %s",nlri_str)                                                     
                                                    nlri_counter = nlri_counter + 5 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 5
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes) 
                                                    self.accepted_prefixes_set.add(nlri_str)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                    #self.logger.info("------------------------------------------")
                                                elif nlriValueValue27 == 1: #prefix of type X.X.0.0
                                                    #self.logger.info("nlriValueValue27 == 1")
                                                    #self.logger.info("NLRI: %s.%s.%s.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0]))
                                                    #nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0])
                                                    #self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split[0]),str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlriValue2[0])) 
                                                    nlri_str = str(nlri_split[0])+"."+str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+"/"+str(nlriValue2[0])
                                                    #self.logger.info("NLRI STRING > 24: %s",nlri_str)                                                      
                                                    nlri_counter = nlri_counter + 5 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 5
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes) 
                                                    self.accepted_prefixes_set.add(nlri_str)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                    #self.logger.info("------------------------------------------") 
                                                elif nlriValueValue28 == 1: #prefix of type X.X.0.0
                                                    #self.logger.info("nlriValueValue28 == 1")
                                                    #self.logger.info("NLRI: %s.%s.%s.96/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0])) 
                                                    #nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0]) 
                                                    #self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split[0]),str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlriValue2[0])) 
                                                    nlri_str = str(nlri_split[0])+"."+str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+"/"+str(nlriValue2[0])
                                                    #self.logger.info("NLRI STRING > 24: %s",nlri_str)                                                    
                                                    nlri_counter = nlri_counter + 5 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 5
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                    #self.logger.info("------------------------------------------") 
                                                elif nlriValueValue32 == 1: #prefix of type X.X.0.0
                                                    #self.logger.info("nlriValueValue32 == 1")
                                                    #self.logger.info("NLRI: %s.%s.%s.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0]))
                                                    #nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0])
                                                    #self.logger.info("NLRI: %s.%s.%s.%s/%s", str(nlri_split[0]),str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlriValue2[0])) 
                                                    nlri_str = str(nlri_split[0])+"."+str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+"/"+str(nlriValue2[0])
                                                    #self.logger.info("NLRI STRING > 24: %s",nlri_str)                                                      
                                                    nlri_counter = nlri_counter + 5 + nlri_zero  
                                                    self.bgp_message_sum = self.bgp_message_sum + 5
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                    #self.logger.info("------------------------------------------") 
                                                else:
                                                    #self.logger.info("nlriValueLen3 == 0")
                                                    #self.logger.info("NLRI: %s.%s.%s.0/%s", str(nlri_split[1]),str(nlri_split[2]),str(nlri_split[3]),str(nlri_split[0])) 
                                                    nlri_str = str(nlri_split[1])+"."+str(nlri_split[2])+"."+str(nlri_split[3])+".0/"+str(nlri_split[0]) 
                                                    #self.logger.info("------------------------------------------") 
                                                    nlri_counter = nlri_counter + 4 + nlri_zero
                                                    self.bgp_message_sum = self.bgp_message_sum + 4
                                                    self.total_number_prefixes = self.total_number_prefixes + 1 
                                                    #self.logger.info("self.total_number_prefixes: %d",self.total_number_prefixes)
                                                    self.accepted_prefixes_set.add(nlri_str)
						    if nlri_str == "184.164.226.0/24":
							current_time = datetime.now().strftime("%H:%M:%S")
							to_print = self.as_path_list_str + "\n" + current_time
							f = open('/home/ubuntu/update_file.txt','a')
	    						f.write(to_print)
							f.write('\n')
	    						f.close()
							self.logger.info("Time 184.164.226.0/24 prefix arrived: %s",current_time)
                                                    self.logger.info("Number of accepted prefixes: %d",len(self.accepted_prefixes_set))
                                                nlriValueLen3 = 0
                                                
                                    
                                        
                                    if self.previous_buffer_len > 0:
                                        #self.logger.info("self.previous_buffer_len > 0: %d",self.previous_buffer_len)
                                        if self.bgp_type != 4:
                                            bgp_iterator = self.bgp_header_end + self.total_path_attribute_len + nlri_counter - b
                                            #self.logger.info("bgp_iterator: %d",bgp_iterator)
                                            add_nlri_to_bgp_iterator = 0
                                            if updated_packet_total_len == 0:
                                                packet_total_len = packet_total_len + bgp_iterator
                                                #self.logger.info("updated_packet_total_len: %d",updated_packet_total_len)
                                                updated_packet_total_len = 0
                                        #if self.extra_buffer == 0:
                                        #    self.packet_buffer_len = bgp_iterator
                                        #    self.extra_buffer == 1
                                    elif self.bgp_type != 4:
                                        #self.logger.info("self.previous_buffer_len <=0: %d",self.previous_buffer_len)
                                        if type_unfeasible_len_before_buffer_len_zero == 1:
                                            #bgp_iterator = 4 + self.bgp_total_path_att_len + nlri_counter - b
                                            bgp_iterator = 4 + self.bgp_total_path_att_len + nlri_counter
                                            #self.logger.info("type_unfeasible_len_before_buffer_len_zero == 1")
                                            add_nlri_to_bgp_iterator = 0
                                            enable_bgp_iterator_total_increment = 1
                                        #elif enable_bgp_iterator_total_increment == 1:
                                            #self.logger.info("bgp_iterator = bgp_iterator: %d + self.bgp_length: %d",bgp_iterator,self.bgp_length)    
                                            #bgp_iterator = bgp_iterator + self.bgp_header_end
                                        #self.logger.info("bgp_iterator: %d",bgp_iterator)                                        
                                    if add_nlri_to_bgp_iterator == 1 and type_unfeasible_len_before_buffer_len_zero == 0:
                                        bgp_iterator = bgp_iterator + nlri_counter
                                        #self.logger.info("updated bgp_iterator: %d",bgp_iterator)
                                        add_nlri_to_bgp_iterator = 0
                                    #self.logger.info("packet_total_len: %d",packet_total_len)
                                    #self.logger.info("******************************************")      
                            #elif bgp_version == 3:
                             #   self.logger.info("BGP Type: 3-NOTIFICATION")
                            #elif bgp_version == 4:
                             #   self.logger.info("BGP Type: 4-KEEPALIVE")                   
 
            #some other IP packet like IGMP
            else :
                print('Protocol other than TCP/UDP/ICMP')

    def eth_addr(self,a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

    def sendMessage(self,msg):
        self.logger.info("sendMessage called!")
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest = (bgpSpeakerIp, port)
        tcp.connect(dest)
        self.logger.info("Message sent to BGP speaker")
        tcp.send (msg)

