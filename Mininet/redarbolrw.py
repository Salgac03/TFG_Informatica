from mininet.net import Mininet         # Para crear y gestionar la red
from mininet.topo import Topo             # Para definir la topología
from mininet.node import Node, CPULimitedHost, OVSKernelSwitch  # Para crear hosts y routers personalizados
from mininet.link import TCLink             # Para enlaces con control de tráfico
from mininet.cli import CLI                 # Para interactuar con la red desde la línea de comandos
from mininet.log import setLogLevel
from mininet.node import OVSController
from mininet.topo import Topo

class MyRouter(Node):
    '''
    Debido a que no existe una clase Router en Mininet la tenemos que crear.
    Para ello hacemos que herede de Node y que su configuración a parte de la
    básica de Node, añada el reenvío de paquetes IPv4.
    '''
    def config(self, **params):
        super(MyRouter, self).config(**params)  # Configura el nodo base
        self.cmd('sysctl -w net.ipv4.ip_forward=1') # Activa el forwarding de paquetes IPv4 (el enrutamiento)

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(MyRouter, self).terminate()

class MyTopo(Topo):
    '''
    Creamos una topología de red que tiene 5 host, 2 switches y un router.

        hsrc: Host que envía los paquetes legítimos y ransomware de manera aleatoria.
        s1: Switch al que está conectado el host src, a su vez está conectado a r1.
        r1: Router de la red al que están conectados s1 y s2, permite la interconexión entre hsrc a 4 y hdst
        s2: Switch al que está conectado hdst y a r1.
        hdst: Host target que filtra.
    '''
    def build(self):
        '''
        Método para construir la topología de red
        '''

        # Crear hosts
        hsrc = self.addHost('hsrc', ip='10.0.1.1/24')
        hdst = self.addHost('hdst', ip='10.0.2.1/24')

        # Crear switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Agregar enrutador
        r1 = self.addNode('r1', cls=MyRouter, ip='10.0.1.254/24')

        # Conectar hosts al switch s1
        self.addLink(hsrc, s1)

        # Conectar el enrutador a s1 y s2
        self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip': '10.0.1.254/24'})
        self.addLink(s2, r1, intfName2='r1-eth2', params2={'ip': '10.0.2.254/24'})

        # Conectar hdst al switch s2
        self.addLink(hdst, s2)

def run():
    '''
    Función para ejecutar la red
    '''

    net = Mininet(topo=MyTopo(), link=TCLink, controller=OVSController)
    # Configuración por defecto de NAT
    net.addNAT().configDefault()
    net.start()

    # Configuramos las rutas de los hosts para que usen el Router
    net['hsrc'].cmd('ip route add default via 10.0.1.254') # Corregido: la ruta por defecto debe ir por la interfaz del router en su red
    net['hdst'].cmd('ip route add default via 10.0.2.254')

    # Montar el sistema de archivos BPF en el nodo hdst
    net['hdst'].cmd('sudo mount -t bpf bpf /sys/fs/bpf')

    # Línea de comandos para interactuar con la topología creada
    CLI(net)

    # Paramos la red
    net.stop()

if __name__  == '__main__':
    setLogLevel('info')
    run()
