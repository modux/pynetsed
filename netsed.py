#!/usr/bin/python

'''
Inline packet content replace

Modify packets during man in the middle, routing or network debugging

Written by Sash (@secdefect)
External Python module inclusion added by KS

Dependancies 

 - scapy
 - nfqueue

'''
  
from scapy.all import *
import nfqueue
import time, argparse, re, os, socket, sys, random
#from dpkt import *
  

class Netsed():

  
  def __init__(self):
  
    #track which packets have been sent so they are not resniffed after modification
    self.pkt_trk={}
    self.qnum=random.randrange(100,4096)
  
    self.port=0
    self.proto=""
    self.intface_pri=""
    self.iptables=[]
    self.passthrough=False	
    self.process_pkt={"TCP": self.process_tcp, "UDP":self.process_udp, "ICMP": self.process_icmp}

  def search_and_replace(self,pkt):
    global regex_flags, args 
            
    if pkt.haslayer(Raw):
      
      if re.search(args.regex[0],pkt[Raw].load,regex_flags):
        
        old_len=len(pkt[Raw])
        
        pkt[Raw].load=re.sub(args.regex[0],args.replace[0],pkt[Raw].load,regex_flags)

				#calculate expected response packet ack            
        new_seq=int(pkt[TCP].seq)+len(pkt[Raw])

        expected_ack=int(pkt[TCP].seq)+old_len

        self.pkt_trk[str(new_seq)]=str(expected_ack)
          
        return pkt
  
      else:
  
        return pkt  
    else:
      return pkt
  
  def run(self):
    print "sniffing..."
    self.build_iptables()
    q=nfqueue.queue()
    if not self.passthrough:
      
      q.set_callback(self.process_pkt[self.proto])
    else:
      print "[passthrough mode]"
      q.set_callback(self.through)
    q.fast_open(self.qnum, socket.AF_INET)
    q.set_queue_maxlen(1000000)

 #   q.create_queue(self.qnum)
    try:
      q.try_run()
    except KeyboardInterrupt:
      q.unbind(socket.AF_INET)
      q.close()
      self.kill_self()

  def through(self,nfpkt):
    
    awd=IP(nfpkt.get_data()).command()
    nfpkt.set_verdict(nfqueue.NF_ACCEPT)
    
    sys.stdout.flush()  
    return 1

  def kill_self(self):
  	#remove iptables 
	  for i in self.iptables:
      
	    os.system("iptables -D "+i)

  def process_tcp(self,nfpkt):
    #pat=re.compile(chr(192)+chr(168)+chr(61))
    
    pkt=IP(nfpkt.get_data())
    
    
    orig_pkt=pkt                
  
    #check if this is a response packet, modify ACK to match accordingly
    if self.pkt_trk.get(str(pkt[TCP].ack)):
      pkt_details=self.pkt_trk[str(pkt[TCP].ack)]

      pkt[TCP].ack=int(pkt_details)   
     
      try:
        pkt_details_lt=int(pkt_details)-1
        pkt[TCP].options[5]=('SAck', (int(pkt_details_lt), int(pkt_details)))
      except:
        print 
    
    pkt=self.search_and_replace(pkt)
    
    #check if packet has been modified at all
    if pkt != IP(nfpkt.get_data()):
      
      del pkt[IP].len
       
      del pkt[IP].chksum
      del pkt[TCP].chksum
			
			#output applicationb side packets (inside of kernel) to debug interface
      #if self.debug:
      #  if pkt[IP].dst==self.localip:
      #    sendp(Ether()/pkt,iface=self.debug)
      #  else:
      #    sendp(Ether()/orig_pkt,iface=self.debug)
    
      nfpkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
    else:
      nfpkt.set_verdict(nfqueue.NF_ACCEPT)
   
      if self.debug:
				sendp(Ether()/pkt,iface=self.debug)
  def process_udp(nfpkt):
    print    
  def process_icmp(nfpkt):
    print    
  def build_iptables(self):
    
    if self.mode=="br":
      print
    else:
      self.iptables.append(("INPUT -i " + self.intface_pri +
                                    " -p " +  self.proto +
                                    " --sport " + str(self.port) +
                                    " -j NFQUEUE --queue-num " + str(self.qnum)))


      self.iptables.append(("OUTPUT -o " + self.intface_pri +
                                    " -p " +  self.proto +
                                    " --dport " + str(self.port) +
                                    " -j NFQUEUE --queue-num " + str(self.qnum)))
      
    for i in self.iptables:
      os.system("iptables -I " + i)
   
def user_choice():
  yes = set(['yes','y', 'ye', ''])
  
  choice = raw_input().lower()
  if choice in yes:
   return True
  else:
   return False
    
         
def main():
  global args
  parser = argparse.ArgumentParser(description="Network SED for on the wire find and replace",
                                    usage="netsed.py (-T,-U,-I) -p PORT [options] REPLACE_REGEX WITH_THIS")
  
  parser.add_argument('regex',metavar='REGEX',type=str,nargs=1,
    help='Regex expression to match')
  parser.add_argument('replace',metavar='NEW_VALUE',type=str,nargs=1,
    help='REPLACE VALUE')
  parser.add_argument('-T', '--tcp', dest='tcp', default=False, action='store_true', help="Use protocol TCP")
  parser.add_argument('-U', '--udp', dest='udp', default=False, action='store_true', help="Use protocol UDP")
  parser.add_argument('-I', '--icmp', dest='icmp', default=False, action='store_true', help="Use protocol ICMP")
  parser.add_argument('-i','--in-interface',dest='intface_sec', type=str,metavar="eth1",
    help='"In" interface')
  parser.add_argument('-o','--out-interface',dest='intface_pri', type=str,metavar="eth0",
    help='"Out" interface',default="eth0")  
  parser.add_argument('-r', '--remote-host', type=str, metavar="x.x.x.x", help="IP address of remote host")
  parser.add_argument('-p','--port', type=str, help='Traffic filter expression (tcpdump format)')  
  parser.add_argument('-f','--regex-flags',dest='regex_flags',type=str,metavar="FLAGS",
    help='Regex Python flags, comma separated (e.g. I,U)')
  parser.add_argument("-c","--python-code",dest="python",type=str,metavar="FILE",
    help="Python module which contains a process function that does processing", )
  parser.add_argument('-m','--mode',dest='mode', type=str,
    help='Mode to run the app in, use "br" or "out". br is used in mitm, out is used for local outbound traffic',default="out")
  parser.add_argument('-d', '--debug-interface',dest="debug",action="store", default=None, help="Interface to send debug packets out of for monitoring - 'lo' for loopback")  
  parser.add_argument('-t', '--pass-through', dest="passthrough", action="store_true", default=False, help="When debugging performance, test the connection can be passed through within modification")

  args=parser.parse_args()
      
  if args.python:
    import importlib
    try:
      m=importlib.import_module(args.python)
      processpkt=m.process
    except Exception,e:
      print "Error: couldn't load your Python module, sorry"
      print str(e)
      sys.exit(-1)
 
   

  if not args.regex or not args.replace:
    print "ERROR: Missing regex or replace"
    sys.exit(-1)

  global regex_flags
  regex_flags=0
  if args.regex_flags:
    for flag in parser.regex_flags.strip().split(","):
      try:
        regex_flags=regex_flags | getattr(re,flag)
      except AttributeError:
        print "Unknown flag: %s" % flag
        sys.exit(-1)
    
  if args.mode=="br":
    ipfwd = open('/proc/sys/net/ipv4/ip_forward').read()
  
    if '1' not in ipfwd:
      print 'IP forwarding not enabled [set to 1] in file /proc/sys/net/ipv4/ip_forward'
      print 'Do you want to enable it now?'
      if  user_choice():
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

   
  ns=Netsed()

  if args.tcp:
    ns.proto="TCP"
  elif args.udp:
    ns.proto="UDP"
  elif args.icmp:
    ns.proto="ICMP"
  else:
    "Print you must select a protocol"
    sys.exit(-1)

  ns.port=args.port
  ns.intface_pri=args.intface_pri
  ns.mode=args.mode
  ns.debug=args.debug
  ns.passthrough=args.passthrough
  ns.run()
  
if __name__=="__main__":
    main()
