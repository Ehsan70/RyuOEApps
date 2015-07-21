from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
import logging
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.icmp import icmp
from ryu.lib.packet.ipv6 import ipv6
from ryu.ofproto import ofproto_v1_3, ofproto_v1_2, ofproto_v1_0
from ryu.base import app_manager
from ryu.lib.packet import packet
from ryu.topology import event
from ryu.topology.switches import LLDPPacket, Link

LOG = logging.getLogger(__name__)

__author__ = 'Ehsan'

class SimpleOpticalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleOpticalController, self).__init__(*args, **kwargs)
        self.dpset = {} #data['dpset']
        self.waiters = {} #data['waiters']

    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPDescStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPMeterStatsReply,
                 ofp_event.EventOFPMeterFeaturesStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPGroupStatsReply,
                 ofp_event.EventOFPGroupFeaturesStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

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

    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        print "#############################################"
        datapath = msg.datapath
        print "datapath id: "+str(datapath.id)
        port = msg.match['in_port']
        print "port: "+str(port)
        pkt = packet.Packet(data=msg.data)
        self.logger.info("packet-in: %s" % (pkt,))

        pkt_ethernet_list = pkt.get_protocols(ethernet)
        if pkt_ethernet_list:
            pkt_ethernet = pkt_ethernet_list[0]
            print ("pkt_ethernet: " + str(pkt_ethernet))
            print ("pkt_ethernet:dst: " + str(pkt_ethernet.dst))
            print ("pkt_ethernet:src: " + str(pkt_ethernet.src))
            print ("pkt_ethernet:ethertype: " + str(pkt_ethernet.ethertype))

        pkt_ipv6_list = pkt.get_protocols(ipv6)
        if pkt_ipv6_list:
            pkt_ipv6 = pkt_ipv6_list[0]
            print ("pkt_ipv6: " + str(pkt_ipv6))
            print ("pkt_ipv6:dst: " + str(pkt_ipv6.dst))
            print ("pkt_ipv6:src: " + str(pkt_ipv6.src))
            print ("pkt_ipv6:nxt: " + str(pkt_ipv6.nxt))
            print ("pkt_ipv6:hop_limit: " + str(pkt_ipv6.hop_limit))
            print ("pkt_ipv6:ext_hdrs: " + str(pkt_ipv6.ext_hdrs))

        pkt_icmp_list = pkt.get_protocols(icmp)
        if pkt_icmp_list :
            pkt_icmp = pkt_icmp_list[0]
            if pkt_icmp:
                print ("pkt_icmp: "+str(pkt_icmp))
                return

        """
        # Base is from the
        if not self.link_discovery:
            return

        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except LLDPPacket.LLDPUnknownFormat as e:
            # This handler can receive all the packtes which can be
            # not-LLDP packet. Ignore it silently
            return

        dst_dpid = msg.datapath.id
        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            dst_port_no = msg.in_port
        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dst_port_no = msg.match['in_port']
        else:
            LOG.error('cannot accept LLDP. unsupported version. %x',
                      msg.datapath.ofproto.OFP_VERSION)

        src = self._get_port(src_dpid, src_port_no)
        if not src or src.dpid == dst_dpid:
            return
        try:
            self.ports.lldp_received(src)
        except KeyError:
            # There are races between EventOFPPacketIn and
            # EventDPPortAdd. So packet-in event can happend before
            # port add event. In that case key error can happend.
            # LOG.debug('lldp_received: KeyError %s', e)
            pass

        dst = self._get_port(dst_dpid, dst_port_no)
        if not dst:
            return

        old_peer = self.links.get_peer(src)
        # LOG.debug("Packet-In")
        # LOG.debug("  src=%s", src)
        # LOG.debug("  dst=%s", dst)
        # LOG.debug("  old_peer=%s", old_peer)
        if old_peer and old_peer != dst:
            old_link = Link(src, old_peer)
            self.send_event_to_observers(event.EventLinkDelete(old_link))

        link = Link(src, dst)
        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))

        if not self.links.update_link(src, dst):
            # reverse link is not detected yet.
            # So schedule the check early because it's very likely it's up
            self.ports.move_front(dst)
            self.lldp_event.set()
        if self.explicit_drop:
            self._drop_packet(msg)
        """