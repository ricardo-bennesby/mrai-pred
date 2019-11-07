#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, Node
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf

def emptyNet():

    NODE1_IP='192.168.1.102'
    NODE2_IP='192.168.1.103'
    CONTROLLER_IP='192.168.1.103'

    net = Mininet( topo=None,
                   build=False)

    net.addController( 'c0',
                      controller=RemoteController,
                      ip=CONTROLLER_IP,
                      port=6633)

    h1 = net.addHost( 'h1', ip='10.0.0.1' )
    h2 = net.addHost( 'h2', ip='10.0.0.2' )
    s1 = net.addSwitch( 's1' )
    net.addLink( h1, s1 )
    net.addLink( h2, s1 )

    # Delete old tunnel if still exists
    s1.cmd('ip tun del s1-gre1')
    # Create GRE tunnel
    s1.cmd('ip li ad s1-gre1 type gretap local '+NODE1_IP+' remote '+NODE2_IP+' ttl 64')
    s1.cmd('ip li se dev s1-gre1 up')
    Intf( 's1-gre1', node=s1 )

    net.start()
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    emptyNet()
