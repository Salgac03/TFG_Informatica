# Pruebas con árboles de decisión

## Origen DB

Para las Pruebas voy a usar las siguientes BD:
	- Bank Marketing (Licencia Creative Commons Attribution 4.0 International): https://archive.ics.uci.edu/dataset/222/bank+marketing



Algunas DBs de UCI serán cargadas desde su módulo python

## Conclusiones
Las Pruebas 1, 2 y 3 son exactamente el mismo programa con una sola diferencia, el parámetro `max_depth` varía, con esto he intentado
ver como afecta la profundidad del árbol a su complejidad y su exactitud. He observado que al menos a partir de un `max_depth` 4, no se
consigue ninguna mejoría en la exactitud, por lo que todo lo que se obtiene a partir de ahí, es un sobreajuste costoso computacionalmente.

## Citas
Moro, S., Rita, P., & Cortez, P. (2014). Bank Marketing [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C5K306.
