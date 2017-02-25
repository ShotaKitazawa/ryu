import logging
import threading
import http.client
import sys
import time

from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet


LOG = logging.getLogger('SimpleForward')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

SERVER_IPADDR = ["10.10.11.11","10.10.11.12"]
SERVER_MACADDR = ["00:0c:29:24:93:13", "00:0c:29:74:37:ee"]
OUTER_IPADDR = "192.168.38.100"
INNER_IPADDR = "10.10.11.1"
OUTER_MACADDR = "01:01:01:01:01:01"
INNER_MACADDR = "02:02:02:02:02:02"
OUTER_PORT = 1
INNER_PORT = 2
TCP_HTTP = 80
count = 50000


class SimpleForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    CLIENT_MACADDR = None
    HOST_MACADDR2 = None

    def __init__(self, *args, **kwargs):
        super(SimpleForward, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

        match = ofproto_parser.OFPMatch()
        actions = [ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)
        LOG.debug("Switch Ready.")

    def install_table_miss(self, datapath, dpid):
        datapath.id = dpid

        match = datapath.ofproto_parser.OFPMatch()

        actions = [datapath.ofproto_parser.OFPActionOutput(
            datapath.ofproto.OFPP_CONTROLLER,
            datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=0xffffffff,
            match=match,
            instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)

        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            arpPacket = packet.get_protocol(arp)
            if arpPacket.dst_ip != OUTER_IPADDR and arpPacket.dst_ip != INNER_IPADDR:
                LOG.debug("Miss: This ARP packet is not for me.")
                return 1
            arpPacket = packet.get_protocol(arp)
            self.receive_arp(datapath, packet, etherFrame, inPort)
            return 0
        elif etherFrame.ethertype == ether.ETH_TYPE_IP:
            ipPacket = packet.get_protocol(ipv4)
            if ipPacket.dst != OUTER_IPADDR:
                LOG.debug("Miss: This IP packet is not for me.")
                return 1

            self.receive_ip(datapath, packet, etherFrame, inPort)
            return 1
        else:
            LOG.debug("receive Unknown packet %s => %s (port%d)"
                      % (etherFrame.src, etherFrame.dst, inPort))
            self.print_etherFrame(etherFrame)
            LOG.debug("Drop packet")
            return 2

    def receive_ip(self, datapath, packet, etherFrame, inPort):
        ipPacket = packet.get_protocol(ipv4)
        tcpPacket = packet.get_protocol(tcp)
        LOG.debug("receive IP packet %s => %s (port%d)"
                  % (etherFrame.src, etherFrame.dst, inPort))
        self.print_etherFrame(etherFrame)
        self.print_ipPacket(ipPacket)
        self.print_tcpPacket(tcpPacket)
        LOG.debug("Drop packet")

        if inPort == OUTER_PORT and ipPacket.dst == OUTER_IPADDR:
            self.CLIENT_MACADDR = etherFrame.src
            self.CLIENT_IPADDR = ipPacket.src
            self.CLIENT_TCPADDR = tcpPacket.src_port

        if self.CLIENT_MACADDR != None:
            if tcpPacket.dst_port == TCP_HTTP:
                self.send_flow(datapath)
            else:
                LOG.debug("unknown ip received !")

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)
        if arpPacket.opcode == 1:
            operation = "ARP Request"
            arp_dstIp = arpPacket.dst_ip

        LOG.debug("receive %s %s => %s (port%d)"
                  % (operation, etherFrame.src, etherFrame.dst, inPort))
        self.print_etherFrame(etherFrame)
        self.print_arpPacket(arpPacket)

        if arpPacket.opcode == 1:
            print("arpPacket: ARP Request")
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        if arp_dstIp == OUTER_IPADDR:
            srcMac = OUTER_MACADDR
            outPort = OUTER_PORT
        elif arp_dstIp == INNER_IPADDR:
            srcMac = INNER_MACADDR
            outPort = INNER_PORT
        else:
            LOG.debug("unknown arp requst received !")

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        LOG.debug("send ARP reply %s => %s (port%d)" % (srcMac, dstMac, outPort))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def send_flow(self, datapath):
        global count
        LOG.debug("Send Flow_mod packet for %s", datapath)
        for i in range(len(SERVER_IPADDR)):
            if (count % len(SERVER_IPADDR) == i):
                self.add_flow(datapath, OUTER_PORT, self.CLIENT_MACADDR,
                              OUTER_MACADDR, ether.ETH_TYPE_IP,
                              OUTER_IPADDR, INNER_PORT,
                              self.CLIENT_TCPADDR, TCP_HTTP,
                              INNER_MACADDR, SERVER_MACADDR[i],
                              INNER_IPADDR, SERVER_IPADDR[i],
                              count, TCP_HTTP,)
                self.add_flow(datapath, INNER_PORT, SERVER_MACADDR[i],
                              INNER_MACADDR, ether.ETH_TYPE_IP,
                              INNER_IPADDR, OUTER_PORT,
                              TCP_HTTP, count,
                              OUTER_MACADDR, self.CLIENT_MACADDR,
                              OUTER_IPADDR, self.CLIENT_IPADDR,
                              TCP_HTTP, self.CLIENT_TCPADDR,)
        count += 1

    def add_flow_init(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, inPort, org_srcMac,
                 org_dstMac, ethertype,
                 targetIp, outPort,
                 org_srcTcp, org_dstTcp,
                 mod_srcMac, mod_dstMac,
                 mod_srcIp, mod_dstIp,
                 mod_srcTcp, mod_dstTcp):

        match = datapath.ofproto_parser.OFPMatch(
            in_port=inPort,
            eth_src=org_srcMac,
            eth_dst=org_dstMac,
            eth_type=ethertype,
            ip_proto=6,
            ipv4_dst=targetIp,
            tcp_src=org_srcTcp,
            tcp_dst=org_dstTcp,
        )
        actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=mod_srcMac),
                   datapath.ofproto_parser.OFPActionSetField(eth_dst=mod_dstMac),
                   datapath.ofproto_parser.OFPActionSetField(ipv4_src=mod_srcIp),
                   datapath.ofproto_parser.OFPActionSetField(ipv4_dst=mod_dstIp),
                   datapath.ofproto_parser.OFPActionSetField(tcp_src=mod_srcTcp),
                   datapath.ofproto_parser.OFPActionSetField(tcp_dst=mod_dstTcp),
                   datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                   ]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)
                ]
        mod = datapath.ofproto_parser.OFPFlowMod(
            cookie=0,
            cookie_mask=0,
            flags=datapath.ofproto.OFPFF_CHECK_OVERLAP,
            table_id=0,
            command=datapath.ofproto.OFPFC_ADD,
            datapath=datapath,
            idle_timeout=0,
            hard_timeout=0,
            priority=0xff,
            buffer_id=0xffffffff,
            out_port=datapath.ofproto.OFPP_ANY,
            out_group=datapath.ofproto.OFPG_ANY,
            match=match,
            instructions=inst)
        datapath.send_msg(mod)

    def print_etherFrame(self, etherFrame):
        LOG.debug("---------------------------------------")
        LOG.debug("eth_dst_address :%s", etherFrame.dst)
        LOG.debug("eth_src_address :%s", etherFrame.src)
        LOG.debug("eth_ethertype :0x%04x", etherFrame.ethertype)
        LOG.debug("---------------------------------------")

    def print_arpPacket(self, arpPacket):
        LOG.debug("arp_hwtype :%d", arpPacket.hwtype)
        LOG.debug("arp_proto :0x%04x", arpPacket.proto)
        LOG.debug("arp_hlen :%d", arpPacket.hlen)
        LOG.debug("arp_plen :%d", arpPacket.plen)
        LOG.debug("arp_opcode :%d", arpPacket.opcode)
        LOG.debug("arp_src_mac :%s", arpPacket.src_mac)
        LOG.debug("arp_src_ip :%s", arpPacket.src_ip)
        LOG.debug("arp_dst_mac :%s", arpPacket.dst_mac)
        LOG.debug("arp_dst_ip :%s", arpPacket.dst_ip)
        LOG.debug("---------------------------------------")

    def print_ipPacket(self, ipPacket):
        LOG.debug("ip_version :%d", ipPacket.version)
        LOG.debug("ip_header_length :%d", ipPacket.header_length)
        LOG.debug("ip_tos :%d", ipPacket.tos)
        LOG.debug("ip_total_length :%d", ipPacket.total_length)
        LOG.debug("ip_identification:%d", ipPacket.identification)
        LOG.debug("ip_flags :%d", ipPacket.flags)
        LOG.debug("ip_offset :%d", ipPacket.offset)
        LOG.debug("ip_ttl :%d", ipPacket.ttl)
        LOG.debug("ip_proto :%d", ipPacket.proto)
        LOG.debug("ip_csum :%d", ipPacket.csum)
        LOG.debug("ip_src :%s", ipPacket.src)
        LOG.debug("ip_dst :%s", ipPacket.dst)
        LOG.debug("---------------------------------------")

    def print_tcpPacket(self, tcpPacket):
        LOG.debug("tcp_src :%s", tcpPacket.src_port)
        LOG.debug("tcp_dst :%s", tcpPacket.dst_port)
        LOG.debug("---------------------------------------")
