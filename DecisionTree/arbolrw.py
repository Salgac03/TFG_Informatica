from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import plot_tree
import matplotlib.pyplot as plt
from sklearn.tree import export_text
import pandas as pd

# Especifica la ruta del archivo CSV
csv_file_path = '../dataset.csv'  # Reemplaza con la ruta correcta a tu archivo CSV

# Lista de columnas que NO quieres usar para el entrenamiento (además de la columna objetivo)
columnas_a_excluir = ["eth_src", "eth_dst", "eth_type", "ip_src", "ip_dst"]  # Añade aquí los nombres de las columnas que no quieres usar

# Lee el archivo CSV usando pandas
try:
    df = pd.read_csv(csv_file_path)
except FileNotFoundError:
    print(f"Error: El archivo CSV no se encontró en la ruta: {csv_file_path}")
    exit()

# La última columna es la variable objetivo (Y)
nombre_columna_objetivo = df.columns[-1]
y = df[nombre_columna_objetivo]

# Selecciona las columnas para las características (X), excluyendo la columna objetivo y las columnas especificadas
columnas_caracteristicas = [col for col in df.columns if col != nombre_columna_objetivo and col not in columnas_a_excluir]
x = df[columnas_caracteristicas]

# Pasamos la información de texto a números automáticamente para que
# el modelo pueda funcionar. Esto convertirá columnas categóricas en varias columnas numéricas.
x = pd.get_dummies(x)

# Separamos los datos para test y para entrenamiento (20% test y 80% entrenamiento)
# test_size indica el % usado para el test (0.2/1 = 20%)
# random_state es una semilla de aleatoreidad, ponemos una para que sea
# siempre la misma división de datos.
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

# Como criterio he elegido Gini
# Como la DB podría ser grande, aunque splitter 'best' es lo que quieres,
# ten en cuenta que podría tardar más en datasets grandes.
# He puesto un max_depth de 4 para que no haya sobrecorrección y además computacionalmente cueste menos.
# Puedes ajustarlo según tus necesidades.
# Uso el mismo random_state que antes, al poner un random_state en teoría disminuyo la aleatoreidad entre repeticiones del mismo test
modelo = DecisionTreeClassifier(criterion='gini', splitter='best', max_depth=4, random_state=42)

# construir el árbol
modelo.fit(x_train, y_train)

# Aunque para el TFG no es necesario es interesante ver si con esta
# configuración se obtendría una exactitud más o menos decente
exactitud = modelo.score(x_test, y_test)
print(f'La exactitud del modelo es: {exactitud: .2f}')

# Visualizar el árbol
plt.figure(figsize=(20, 10))
plot_tree(modelo, filled=True, feature_names=x.columns, class_names=y.unique().astype(str)) # Ajusta las clases según tu dataset
plt.show()

# Visualizar el árbol en texto
arbol_texto = export_text(modelo, feature_names=list(x.columns))
print(arbol_texto)
