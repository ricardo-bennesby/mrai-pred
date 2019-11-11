# MRAI-pred Framework

MRAI-pred, to the best of our knowledge, is the first hybrid framework endowed with a learning mechanism that integrates the SDN paradigm within interdomain routing domains to improve the interdomain routing convergence time. This is achieved by  employing the LSTM learning technique that allows the tuning of MRAI value aiming to reduce the convergence time according to learned patterns from collected BGP UPDATE features.

## Getting Started

To deploy and use the MRAI-pred framework, you should first submit an experiment proposal to the PEERING team to be able to send announcements to the Internet and install the required tools listed as prerequisites: 

### Prerequisites

The software tools you should install as a prerequisite to the MRAI-pred Framework:

* [PEERING](https://peering.usc.edu/)
* [Keras with Tensorflow backend](https://www.pyimagesearch.com/2016/11/14/installing-keras-with-tensorflow-backend/)
* [ExaBGP](https://github.com/Exa-Networks/exabgp)
* [Ryu Controller](https://osrg.github.io/ryu/)
* [Mininet](http://mininet.org/download/)

### Configuring connection between SDN experiment with the PEERING MUXes
After the PEERING experiment approval, you will receive the certificate .key and .crt files that show be placed in the certs file. Then, clone the [PEERING](https://github.com/PEERINGTestbed/client#peering-account-setup) repository and follow the described steps to configure OpenVPN and learn how to use PEERING.  

To list the PEERING MUXes and their status do:

```console
$ cd client
$ sudo ./peering openvpn status
```

To open up the connection with a PEERING MUX, you should do:

```console
$ sudo ./peering openvpn up neu01
```

To run ryu, opens a new terminal or new tab in console and run the command:

```console
$ cd ~/ryu
$ ryu-manager --verbose ryu/app/backup/simple_switch_13_mrai.py
```

To run mininet with the configured script, opens up a new termonal or new tabs and do:

```console
$ cd ~/mininet/examples
$ sudo python new_int_mn_peering.py "0"
```

Then, a third terminal should be opened to run the script that loads the weights of trained model and that is responsible for sending the messages to ExaBGP:

```console
$ python tcp_socket_server.py
```


## Authors

* **Ricardo Bennesby** - [Scholar](https://scholar.google.com.br/citations?user=WZtAvu8AAAAJ&hl=pt-BR/)
* **Edjard Mota** - [Scholar](https://scholar.google.com.br/citations?user=7WhE5ucAAAAJ&hl=pt-BR)
* **Paulo Fonseca** - [Scholar](https://scholar.google.com.br/citations?user=e-w1zY4AAAAJ&hl=pt-BR)
* **Alexandre Passito** 

## References

- [PEERING testbed paper](http://conferences.sigcomm.org/hotnets/2014/papers/hotnets-XIII-final159.pdf): Understand the PEEERING platform and how it can provide real interdomain peering and connectivity with the Internet for emulated intradomain experiments.

- [BGP Routing Convergence survey](https://ieeexplore.ieee.org/document/7964680): A survey on the issues and the state-of-the-art efforts to address the BGP routing convergence delay problem. 

## Acknowledgments

* We would like to thank prof. [Italo Cunha](https://scholar.google.com.br/citations?user=bTAky1EAAAAJ&hl=pt-BR) and the PEERING team for all the suport provided to our experiments. 

