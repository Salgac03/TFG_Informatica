from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class SimpleTopo(Topo):
    """
    Topología simple compuesta por:
      - hsrc: Host origen con IP 10.0.1.1/24
      - hdst: Host destino con IP 10.0.2.1/24
      - s1: Switch conectado a ambos hosts
    """
    def build(self):
        # Crear hosts
        hsrc = self.addHost('hsrc', ip='10.0.1.1/24')
        hdst = self.addHost('hdst', ip='10.0.2.1/24')

        # Crear switch
        s1 = self.addSwitch('s1')

        # Conectar hosts al switch
        self.addLink(hsrc, s1)
        self.addLink(hdst, s1)

def run():
    """
    Configuración y ejecución de la red.
    """
    topo = SimpleTopo()
    net = Mininet(topo=topo, link=TCLink, controller=OVSController)
    net.start()

    net['hdst'].cmd('sudo mount -t bpf bpf /sys/fs/bpf')

    # Realizar un ping de verificación desde hsrc a hdst
    print("Ping test from hsrc to hdst:")
    print(net['hsrc'].cmd('ping -c 3 10.0.2.1'))

    # Abrir la CLI para pruebas adicionales
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
