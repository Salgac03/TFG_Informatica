from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class SimpleTopo(Topo):
    """
    Topología simple compuesta por:
      - hsrc: Host origen con IP 10.0.1.1/24 y MAC constante
      - hdst: Host destino con IP 10.0.1.2/24 y MAC constante
      - s1: Switch conectado a ambos hosts
    """
    def build(self):
        hsrc = self.addHost(
            'hsrc',
            ip='10.0.1.1/24',
            mac='00:00:00:00:01:01'
        )
        hdst = self.addHost(
            'hdst',
            ip='10.0.1.2/24',
            mac='00:00:00:00:02:02'
        )

        s1 = self.addSwitch('s1')
        self.addLink(hsrc, s1)
        self.addLink(hdst, s1)

def run():
    topo = SimpleTopo()

    net = Mininet(
        topo=topo,
        controller=OVSController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False
    )

    net.start()

    # Montar BPF (necesario para eBPF/XDP)
    net['hdst'].cmd('mount -t bpf bpf /sys/fs/bpf')

    print("Ping test from hsrc to hdst:")
    print(net['hsrc'].cmd('ping -c 3 10.0.1.2'))

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
