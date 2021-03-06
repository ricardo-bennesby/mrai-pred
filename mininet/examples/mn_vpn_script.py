#!/usr/bin/python

"""
This example shows how to add an interface (for example a real
hardware interface) to a network after the network is created.
"""

import re
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.link import TCLink
from mininet.topolib import TreeTopo
from mininet.topo import SingleSwitchTopo
from mininet.util import quietRun
from mininet.node import RemoteController
from mininet.node import OVSController
from mininet.node import OVSSwitch
from mininet.node import UserSwitch
from mininet.node import CPULimitedHost
from functools import partial

#from topo14_fullMesh5_testupdate import *
#from topo13_2fullMesh4_testupdate import *
#from topo2_fullMesh15 import *
#from topo8_fullMesh6_testupdate import *
#from topo9_fullMesh15_testupdate import *
#from topo10_fullMesh10_testupdate import *
#from topo7_pyramid6_testupdate import *
#from topo12_tree6_testupdate import *
#from topo3_fullMesh10_testupdate import *
#from topo15_fullMesh3fullMesh4_testupdate import *
#from topo16_fullMesh8_2links_testupdate import *
#from topo17_custom_8node_testupdate import *
#from topo18_custom_8node_testupdate2 import *
#from topo19_fullMesh5Ring3_testupdate import *
#from topo20_b_clique6_testupdate import *
#from topo21_c_grid8_testupdate import *
#from topo22_custom_grid8_testupdate import *
#from topo23_custom_grid8_2_testupdate import *
#from topo24_focus_5_testupdate import *
#from topo26_focus_6_testupdate import *
#from topo27_focus_7_testupdate import *
#from topo29_focus_8_testupdate import *
#from topo30_sample_real_testupdate import *
#from topo_31_full_mesh_5_3_testupdate import *
#from topo11_fullMesh8_testupdate import *
#from topox_fullMesh4_testupdate import *

# First define your topology in the file 'bgpQuaggaConfigFileGenerator.py'... 
# ...In this file the dictionaries dic1, dic2, and dic3 are defined

# Modify this class if you want to use a different switch implementation
class CustomSwitch(UserSwitch):
	def __init__(self, name, **params):
		UserSwitch.__init__(self, name=name, datapath='user', **params)

def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    if ( ' %s:' % intf ) not in quietRun( 'ip link show' ):
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun( 'ifconfig ' + intf ) )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )

if __name__ == '__main__':
    setLogLevel( 'info' )

    #numberOfLinks = len(links)
   
    MRAICurrentValue = int(sys.argv[1])
    #MRAICurrentValue = 30

    print("Current MRAI value: %d" % MRAICurrentValue)

    # try to get hw intf from the command line; by default, use eth1
    #intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    #intfName = 'eth13'
    #intfTap = 'eth13'
    intfTap = 'tap1'
    #info( '*** Connecting to hw intf: %s\n' % intfName )
    

    #info( '*** Checking', intfName, '\n' )
    #checkIntf( intfName )

    info( '*** Checking', intfTap, '\n' )
    #checkIntf( intfTap )

    info( '*** Creating network\n' )

    topo = SingleSwitchTopo( 0 )
       
    #net = Mininet( topo=topo, switch=CustomSwitch, controller=partial( RemoteController, ip='192.168.1.17', port=6633  ), host=CPULimitedHost, link=TCLink) 
    #net = Mininet( topo=topo, switch=UserSwitch, controller=partial( RemoteController, ip='192.168.1.103', port=6633  ))
    net = Mininet( topo=topo, switch=OVSSwitch, controller=partial( RemoteController, ip='192.168.1.103', port=6633  ))
	
    #net = Mininet( topo=topo, switch=CustomSwitch, controller=OVSController) 
    #net = Mininet( topo=topo, switch=OVSSwitch, controller=partial( RemoteController, ip='192.168.0.149', port=6633  ), host=CPULimitedHost, link=TCLink)

    root = net.addHost( 'root', inNamespace=False, ip='192.168.1.112/24' )
    #bgp = net.addHost( 'bgp', ip="192.168.1.110")

    #root = net.addHost( 'root', inNamespace=False, ip='192.168.0.112/24' )
    #bgp = net.addHost( 'bgp', ip="192.168.0.110" )
    #bgp = net.addHost( 'bgp', ip="100.65.128.3" )

    bgp = net.addHost( 'bgp', ip="192.168.1.110")

    #bgp.cmdPrint( 'ip addr flush dev tap5' )

    s1 = net.switches[ 0 ]
    #s1.cmdPrint('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    #s1.cmd('ovs-vsctl add-port s1 tap5')
    #s1.cmd('ovs-vsctl add-port s1 tap5')
    #s1.cmd('ovs-vsctl add-port br_OVS-tap5')

    info( '*** Adding hardware interface', intfTap, 'to switch',
          s1.name, '\n' )
    _intf = Intf( intfTap, node=s1 )
    #s1.popen('ovs-vsctl add-port s1 '+intfTap)
    #node.addIntf( self, port=port, moveIntfFn=moveIntfFn )
    #s1.addIntf(s1.name,intfTap)	

    #s1.cmdPrint('sudo ifconfig tap5 0.0.0.0')
    #s1.setIP('0.0.0.0', intf='eth2')
    #s1.setIP('0.0.0.0')
    #time.sleep(1)
        
    #x = 0
    #while x < numberOfLinks:
	#link = links[x]
	#s1.cmdPrint('sudo rm /var/run/quagga/'+link[0]+'.pid')	
    	#x = x+1

    i = 0

    net.addLink( root, bgp )
    net.addLink( bgp, s1 ) 
    #net.addLink( root, bgp )
    
    port = 2000
    count = 0

    net.start()

    #bgp.cmdPrint( 'ifconfig bgp-eth0 100.69.128.10' )
    #bgp.setIP('100.65.128.3', intf='bgp-eth0')
    root.setIP('192.168.1.112', intf='root-eth0')
    bgp.setIP('192.168.1.110', intf='bgp-eth0')
    bgp.setIP('100.65.128.3', intf='bgp-eth1')

   

    #bgp.cmdPrint('sudo exabgp /etc/exabgp/bgprouter.ini &\n')
    #bgp.cmdPrint('sudo /usr/bin/python /home/ubuntu/mininet/examples/controllingApp.py \n')



    #bgp.cmdPrint('sudo /etc/init.d/quagga stop' )
    #bgp.cmdPrint('sudo quagga /etc/quagga/bgpd.conf &\n')
    #bgp.cmdPrint('sudo rm /var/run/quagga/bgpd.conf.pid')
    #bgp.cmdPrint('sudo /usr/lib/quagga/bgpd -f /etc/quagga/bgpd.conf -i /var/run/quagga/bgpd.conf.pid -p 179 -P '+str(port+count)+' &\n')
    #bgp.cmdPrint('sudo /etc/init.d/quagga restart' )
    #bgp.cmdPrint('sudo /usr/lib/quagga/bgpd -f /etc/quagga/bgpd.conf -i /var/run/quagga/bgpd.pid -p 179 &\n')

    bgp.cmdPrint('ifconfig\n')

    #time.sleep(1)

    #bgp.cmdPrint('ifconfig\n')

    CLI( net )
    #time.sleep(130)

    #net.stop()
