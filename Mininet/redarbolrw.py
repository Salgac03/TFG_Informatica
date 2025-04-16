from mininet.net import Mininet         # Para crear y gestionar la red
from mininet.topo import Topo             # Para definir la topología
from mininet.node import Node, OVSKernelSwitch
from mininet.link import TCLink           # Para enlaces con control de tráfico
from mininet.cli import CLI             # Para interactuar con la red desde la línea de comandos
from mininet.log import setLogLevel
from mininet.node import OVSController

class MyRouter(Node):
    """
    Creamos un nodo Router que habilita el IP forwarding.
    """
    def config(self, **params):
        super(MyRouter, self).config(**params)
        # Habilitamos el forwarding de IPv4 para que rutee tráfico entre sus interfaces
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(MyRouter, self).terminate()

class MyTopo(Topo):
    """
    Topología compuesta por:
      - hsrc: host origen con IP 10.0.1.1/24
      - hdst: host destino con IP 10.0.2.1/24
      - s1 y s2: switches conectados a hsrc y hdst respectivamente
      - r1: router con dos interfaces, r1-eth1 en 10.0.1.254/24 y r1-eth2 en 10.0.2.254/24,
            encargándose de la interconexión entre las dos subredes.
    """
    def build(self):
        # Crear hosts
        hsrc = self.addHost('hsrc', ip='10.0.1.1/24')
        hdst = self.addHost('hdst', ip='10.0.2.1/24')

        # Crear switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Agregar router: a priori asignamos la IP de la red 10.0.1.0/24;
        # luego se asigna la segunda interfaz manualmente en el enlace a s2.
        r1 = self.addNode('r1', cls=MyRouter, ip='10.0.1.254/24')

        # Conectar hsrc al switch s1
        self.addLink(hsrc, s1)

        # Conectar el router a s1: en la red 10.0.1.0/24 (puerta de enlace para hsrc)
        self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip': '10.0.1.254/24'})

        # Conectar el router a s2: en la red 10.0.2.0/24 (puerta de enlace para hdst)
        self.addLink(s2, r1, intfName2='r1-eth2', params2={'ip': '10.0.2.254/24'})

        # Conectar hdst al switch s2
        self.addLink(hdst, s2)

def run():
    """
    Configuración y ejecución de la red.
    Se agregan rutas y se establecen entradas ARP estáticas para garantizar que los
    paquetes IP enviados desde hsrc usan correctamente el siguiente salto (r1).
    """
    topo = MyTopo()
    net = Mininet(topo=topo, link=TCLink, controller=OVSController)
    
    # NAT no es estrictamente necesario en este caso, pero se deja por defecto.
    net.addNAT().configDefault()
    net.start()

    # Configurar rutas por defecto en los hosts:
    net['hsrc'].cmd('ip route add default via 10.0.1.254')
    net['hdst'].cmd('ip route add default via 10.0.2.254')

    # Establecer entradas ARP estáticas para evitar problemas de resolución:
    # En hsrc, se asigna la MAC de la interfaz r1-eth1 (gateway) para la red 10.0.1.0/24.
    r1_eth1_mac = net['r1'].intf('r1-eth1').MAC()
    net['hsrc'].cmd('arp -s 10.0.1.254 %s' % r1_eth1_mac)

    # En hdst, si se requieren respuestas, se asigna la MAC de la interfaz r1-eth2 del router.
    r1_eth2_mac = net['r1'].intf('r1-eth2').MAC()
    net['hdst'].cmd('arp -s 10.0.2.254 %s' % r1_eth2_mac)

    # Realizar un ping de verificación desde hsrc a hdst:
    print("Ping test from hsrc to hdst:")
    print(net['hsrc'].cmd('ping -c 3 10.0.2.1'))

    # Montar el sistema de archivos BPF en hdst (si es necesario para otros procesos)
    net['hdst'].cmd('sudo mount -t bpf bpf /sys/fs/bpf')

    # Abrir la CLI para pruebas adicionales
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
