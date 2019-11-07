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
from mininet.node import Node

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

#peering_ip = '100.78.128.116'
peering_ip = '100.78.128.6'
#test_ip = '100.78.128.1'
remote_controller_ip = '10.208.2.153'
#remote_controller_ip = '192.168.0.107' 
#remote_controller_ip = '192.168.1.107'

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
   
    MRAICurrentValue = int(sys.argv[1])

    print("Current MRAI value: %d" % MRAICurrentValue)

    intfTap = 'tap14'
    intfTap2 = 'enp0s8'

    #info( '*** Checking', intfTap, '\n' )
    #checkIntf( intfTap )
 
    info( '*** Checking', intfTap2, '\n' )
    checkIntf( intfTap2 )

    info( '*** Creating network\n' )

    topo = SingleSwitchTopo( 0 )
    topo2 = SingleSwitchTopo( 0 )
       
    net = Mininet( topo=topo, switch=OVSSwitch, controller=partial( RemoteController, ip=remote_controller_ip, port=6633  ))
    #net = Mininet( topo=topo, switch=OVSSwitch, controller=partial( RemoteController, ip='10.208.6.70', port=6633  ))
    #net2 = Mininet( topo=topo2, switch=OVSSwitch, controller=partial( RemoteController, ip='192.168.1.103', port=6634  ))

    root = net.addHost( 'root', inNamespace=False )
    root = net.addHost( 'root', inNamespace=False, ip='10.208.3.122/24' )
    bgp = net.addHost( 'bgp', ip=peering_ip )
    #bgp_test = net.addHost( 'bgp_test', ip=test_ip )

    s1 = net.switches[ 0 ]
 
    #s2 = net2.switches[ 0 ]

    net.addLink( bgp, s1 ) 
    #net.addLink( bgp_test, s1 ) 

    info( '*** Adding hardware interface', intfTap2, 'to switch',s1.name, '\n' )
    _intf = Intf( intfTap, node=s1 )
    _intf2 = Intf( intfTap2, node=s1 )

    #s1.setMAC("08:00:27:88:ba:24",intfTap2)
    #mac = s1.MAC(intfTap2)
    #s1.cmdPrint('ifconfig '+ intfTap2 + " 100.78.128.220")
    
    port = 3000
    count = 0

    # Create a node in root namespace and link to switch 0
    #root = Node( 'root', inNamespace=False )
    #intf = net.addLink( root, bgp ).intf1
    net.addLink( root, bgp )

    net.start()

    #net2.start()

    bgp.setIP(peering_ip, intf='bgp-eth0')
    #bgp_test.setIP(test_ip, intf='bgp_test-eth0')
    root.setIP('10.208.3.122/24', intf='root-eth0')
    bgp.setIP('10.208.3.120', intf='bgp-eth1')

    #bgp.cmdPrint('route add default gw 100.78.128.220')
    #bgp.cmdPrint(' arp -s 100.78.128.220 ',mac)

    #bgp.setIP('100.78.128.5', intf='bgp-eth0')
    #root.setIP('10.208.6.122/24', intf='root-eth0')
    #bgp.setIP('10.208.6.120', intf='bgp-eth1')

    bgp.cmdPrint('sudo exabgp /etc/exabgp/bgprouter_ufam.ini \n')

    '''time.sleep(2)
    
    bgp.cmdPrint('ifconfig\n')

    time.sleep(2)
    
    bgp.cmdPrint('ifconfig\n')

    time.sleep(2)
    
    bgp.cmdPrint('ifconfig\n')

    time.sleep(2)
    
    bgp.cmdPrint('ifconfig\n')

    time.sleep(2)
    
    bgp.cmdPrint('ifconfig\n')'''

    '''bgp_test.cmdPrint('sudo exabgp /etc/exabgp/bgprouter_test.ini &\n')

    time.sleep(2)
    
    bgp_test.cmdPrint('ifconfig\n')

    time.sleep(2)
    
    bgp_test.cmdPrint('ifconfig\n')

    time.sleep(2)'''

    CLI( net )
