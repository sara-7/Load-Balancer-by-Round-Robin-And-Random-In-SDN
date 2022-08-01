

from pox.core import core
import pox
log = core.getLogger("iplb") # للحصول على المسجل(الهوست) وتتبع حالة الويب

#كلهم اوبجكت من كلاس 
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST #mac src & dec
from pox.lib.packet.ipv4 import ipv4  #ip src & dec
from pox.lib.packet.arp import arp  # بروتوكول لتحويل ايبي لماك
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid

import pox.openflow.libopenflow_01 as of #إحصائيات تدفق الويب(حركة مرور الويب ومعلومات التسجيل وغيرها)

import time
import random

FLOW_IDLE_TIMEOUT = 10 #ستنتهي صلاحية القاعدة إذا لم تتم مطابقتها في10 ثوانٍ
FLOW_MEMORY_TIMEOUT = 60 * 5



class MemoryEntry (object):
  """
  Record for flows we are balancing

  Table entries in the switch "remember" flows for a period of time, but
  rather than set their expirations to some long value (potentially leading
  to lots of rules for dead connections), we let them expire from the
  switch relatively quickly and remember them here in the controller for
  longer.

  Another tactic would be to increase the timeouts on the switch and use
  the Nicira extension which can match packets with FIN set to remove them
  when the connection closes.
  """
  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT #عند انتهاء مهلة زمنية محددة ، يمكن أن يفرغ مخل السويتش

  @property
  def is_expired (self): #عند انتهاء صلاحية عند انتهاء مدة زمنية محددة مسبقا
    return time.time() > self.timeout

  @property    
  def key1 (self):  #الحصول على خصائص الباكيت
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport

################################################################################3
class iplb (object): #IP load balancer
  """
  A simple IP load balancer

  Give it a service_ip and a list of server IP addresses.  New TCP flows
  to service_ip will be randomly redirected to one of the servers.

  We probe the servers to see if they're alive by sending them ARPs.
  """
  def __init__ (self, connection, service_ip, servers = []):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers] #لوب تلف عالسيرفرات وتعطيها ايبي
    self.con = connection
    self.mac = self.con.eth_addr  #سيتم إعطاء ماك  
    self.live_servers = {} # IP -> MAC,port

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log

     #يتم هنا التأكد من ان هذه ال servers لازالت تعمل من خلال ارسال طلبات ARP 
     # اليها أيضا يتم احتساب وقت لطلب ال ARP لنعتبره لا يعمل بعد مرور الوقت من خلال outstanding_probes  ميثود
    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = 5

    # How long do we wait for an ARP reply before we consider a server dead?
    self.arp_timeout = 3

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)

  def _do_expire (self):
    """
    مسؤولة عن انهاء عمر التدفق بعد انتهاء الوقت الخاص بالطلب 
    هذا يساعد في موضوع المساحة وال ip الخاص بالسيرفر اذا كان 
    لا يعمل السيرفر أي انه لوقت معين يتم احتسابه من خلال outstanding_probes  
    ميثود عندها ننهي عمر الطلب ARP بعد هذا الوقت وبهذا يصبح عنوان ال ip 
    قابل للاستخدام لانه لا يوجد سيرفر يعمل يستخدمه وبالطبع نمسح من الذاكرة أي طلب انتهى

    Expire probes and "memorized" flows

    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at: #اذا اكبر من وقت الصلاحية يعني السيرفر ميت
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:  
          self.log.warn("Server %s down", ip) #رسالة تحذير عند انتهاءوقت الصلاحية
          del self.live_servers[ip] #احذف السيرفر صاحب الايبي من مجموهة السيرفرات الحية

    # Expire old flows
    c = len(self.memory) #طول المومري
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory)) #رسالة تصحيح

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r
 
 ##################################################################################
  def _pick_server (self, key, inport): #اختيار الخادم لطلب جديد
    return random.choice(self.live_servers.keys())
##################################################################################

  def _handle_PacketIn (self, event): #هذه الفنكشن مسؤولة عن تعامل السيرفر مع الباكيت
    inport = event.port
    packet = event.parsed

    def drop (): #اذا كان هناك كلاينت للرد عليه اذا لم يكن اذا نحذف الباكيت من خلال فنكشن
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.log.info("Server %s up", arpp.protosrc) #لو ان السيرفر في ال memory كان none نرسل تحذير انه no server
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()

    # It's TCP.

    ipp = packet.find('ipv4')

    if ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.debug("No client for %s", key) #ونرسل رسالة تحذير انه no client 
        return drop()

      # Refresh time timeout and reinstall.
      entry.refresh()

      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      # Ah, it's for our service IP and needs to be load balanced

      # Do we already know this flow?
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        # Don't know it (hopefully it's new!)
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        # Pick a server for this flow
        server = self._pick_server(key, inport)
        self.log.debug("Directing traffic to %s", server) #الجملة الي بتنطبع بالكونترولر
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry

      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


# Remember which DPID we're operating on (first one to connect)
_dpid = None

#########################################################################################3
def launch (ip, servers, dpid = None):
  global _dpid
  if dpid is not None:
    _dpid = str_to_dpid(dpid)

  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
  ip = IPAddr(ip)


  # We only want to enable ARP Responder *only* on the load balancer switch,
  # so we do some disgusting hackery and then boot it up.
  from proto.arp_responder import ARPResponder
  old_pi = ARPResponder._handle_PacketIn
  def new_pi (self, event):
    if event.dpid == _dpid:
      # Yes, the packet-in is on the right switch
      return old_pi(self, event)
  ARPResponder._handle_PacketIn = new_pi

  # Hackery done.  Now start it.
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})
  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)


  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      if not core.hasComponent('iplb'):
        # Need to initialize first...
        core.registerNew(iplb, event.connection, IPAddr(ip), servers)
        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)


  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp) # Listen for flow stats
