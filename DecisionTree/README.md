# Árboles de decisión

## Pruebas con árboles de decisión

### Origen DB

Para las Pruebas voy a usar las siguientes BD:
	- Bank Marketing (Licencia Creative Commons Attribution 4.0 International): https://archive.ics.uci.edu/dataset/222/bank+marketing



Algunas DBs de UCI serán cargadas desde su módulo python

### Conclusiones
Las Pruebas 1, 2 y 3 son exactamente el mismo programa con una sola diferencia, el parámetro `max_depth` varía, con esto he intentado
ver como afecta la profundidad del árbol a su complejidad y su exactitud. He observado que al menos a partir de un `max_depth` 4, no se
consigue ninguna mejoría en la exactitud, por lo que todo lo que se obtiene a partir de ahí, es un sobreajuste costoso computacionalmente.

## Primer Árbol de Decisión Ransomware

### Origen DB
El dataset utilizado para el árbol de decisión es un fichero csv generado por mí. Su peso es de 294,6 MB para crearlo he usado la versión más 
reciente del script pcap2csv.py a la hora de subir esta actualización, he modificado el script para que una más de dos pcaps al fichero csv y
pueda distinguir los paquetes malware de los legítimos mediante las flags -l y -m, en el momento actual solo se guarda la información de los
paquetes hasta el nivel de aplicación sin entrar en él por el reto que consiste obtener posteriormente estos datos en C a nivel de kernel.

Los ficheros pcap de ransomware los he obtenido de la base de datos generada por los investigadores Eduardo Berrueta, Daniel Morató , Eduardo 
Magaña y Mikel Izal quienes me han dado acceso a la base de datos pues aún no es accesible por todo el mundo, motivo por el que les estoy agradecido
y por el que no hago público el dataset para respetar su trabajo. El fichero pcap de tráfico legítimo lo he generado yo capturando el tráfico
en un día trabajando en un laboratorio de mi universidad, por el uso normal de los dispositivos, capturé tráfico HTTP, HTTPS, DNS, SSH y otros
protocolos. Para poder hacer un árbol de decisión lo más preciso posible, generé tráfico SMB2 copiando un fichero grande a una unidad de almacenamiento
en la CPD de mi universidad.

### Entrenamiento
Como las capturas tanto del malware como del tráfico legítimo usan un número de IPs y direcciones MACs muy limitados, he obviado esta información
para que el árbol de decisión no dependa de estos datos que harían que el filtro se basara en información que realmente no da una ganancia realista.
Como criterio he mantenido Gini debido a su gran fiabilidad y rendimiento y como estrategia de división he mantenido best, temía que esta decisión
pudiera aumentar significativamente el tiempo de ejecución del entrenamiento al haber aumentado el tamaño del dataset, pero de momento esto no ha 
sucedido, si se llegara a este punto cambiaría la estrategia a random. La profundidad máxima del árbol de decisión he decidido que sea cuatro porque
en las pruebas previas a trabajar con el dataset de paquetes de red observé que no se ganaba precisión a partir de esta profundidad, según avance con
el proyecto si lo veo conveniente probaré a darle más profundidad al árbol y comprobaré si se gana eficiencia con más profundidad o si solo hay
un sobreajuste.

### Versión Mejorada
Me di cuenta de que sin querer metí en la lista de columnas que no tenían que ser procesadas para entrenar el árbol de decisión la variable `eth_type`
y decidí volver a entrenar el árbol pero con este parámetro y fue sorprendente ver que la precisión se mantenía pero esta vez con un nivel menos de 
profundidad, es decir profundidad máxima igual a 3 a pesar de que tenía permitido llegar a 4.

## Autogeneración de Código C
Como mejora al árbol de decisión he añadido la capacidad de autogenerar el código BPF/XDP una vez se ha entrenado el árbol de decisión, esto lo consigo
recorriendo de manera recursiva el árbol, después genero la condición con el nombre del feature (parseado a nombre real) y con el threshold, después,
paso la condición por una función que en ciertos casos la sustituye por una condición que sea válida, por ejemplo la condición `src_port <= inf` la cambia 
por la condición `ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP` pues el hecho de que el puerto destino sea menor que infinito solo implica que el 
puerto existe. Una vez la condición es válida si es parte del hijo izquierdo se mete en un if y si es el hijo derecho se mete en un else. He usado un template
jinja con la estructura ya prediseñada del C, haciendo pruebas me he dado cuenta que lo más cómodo y que mejor resultado me ha dado para generar el código es 
obtener los datos de las cabeceras IP antes de realizar el árbol, de manera que ya forman parte del template, si el paquete analizado no tiene cabecera IP
estos datos valen 0.

## Citas
Moro, S., Rita, P., & Cortez, P. (2014). Bank Marketing [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C5K306.

Eduardo Berrueta, Daniel Morató , Eduardo Magaña, Mikel Izal, February 24, 2020, "Open Repository for the Evaluation of Ransomware Detection Tools", IEEE Dataport, doi: https://dx.doi.org/10.21227/qnyn-q136. 
