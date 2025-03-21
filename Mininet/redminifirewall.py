from mininet.net import Mininet             # Para crear y gestionar la red from mininet.topo import Topo               # Para definir la topología
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

        h1 a 4: Hosts que envían al target que corre el minifirewall paquetes desde distintos puertos
        y protocolos (TCP o UDP).
        s1: Switch al que están conectados los hosts 1 a 4, a su vez está conectado a r1.
        r1: Router de la red al que están conectados s1 y s2, permite la interconexión entre h1 a 4 y h5
        s2: Switch al que está conectado h5 y a r1.
        h5: Host target que ejecuta el minifirewall.
    '''
    def build(self):
        '''
        Método para construir la topología de red
        '''

        # Crear hosts
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h2 = self.addHost('h2', ip='10.0.1.2/24')
        h3 = self.addHost('h3', ip='10.0.1.3/24')
        h4 = self.addHost('h4', ip='10.0.1.4/24')
        h5 = self.addHost('h5', ip='10.0.2.1/24')

        # Crear switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Agregar enrutador
        r1 = self.addNode('r1', cls=MyRouter, ip='10.0.1.254/24')

        # Conectar hosts al switch s1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)
        
        # Conectar el enrutador a s1 y s2
        self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip': '10.0.1.254/24'})
        self.addLink(s2, r1, intfName2='r1-eth2', params2={'ip': '10.0.2.254/24'})

        # Conectar h5 al switch s2
        self.addLink(h5, s2)



def run():
    '''
    Función para ejecutar la red
    '''

    net = Mininet(topo=MyTopo(), link=TCLink, controller=OVSController)
    # Configuración por defecto de NAT
    net.addNAT().configDefault()
    net.start()

    # Configuramos las rutas de los hosts para que usen el Router
    for i in range(1,5):
        net[f'h{i}'].cmd('ip route add default via 10.0.1.254')

    net['h5'].cmd('ip route add default via 10.0.2.254')

    # Línea de comandos para interactuar con la topología creada
    CLI(net)

    # Paramos la red
    net.stop()


if __name__  == '__main__':
    run()
