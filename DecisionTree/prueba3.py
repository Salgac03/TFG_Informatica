from re import DEBUG
from ucimlrepo import fetch_ucirepo 
from sklearn.model_selection import train_test_split 
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import plot_tree
import matplotlib.pyplot as plt
from sklearn.tree import export_text
import pandas as pd

# importamos la DB
# fetch dataset 
bank_marketing = fetch_ucirepo(id=222) 
  
# data (as pandas dataframes) 
x = bank_marketing.data.features 
y = bank_marketing.data.targets 
  
# metadata 
print(bank_marketing.metadata) 
  
# variable information 
print(bank_marketing.variables) 

# pasamos la información de texto a números automáticamente para que
# el modelo pueda funcionar
x = pd.get_dummies(x)

# Separamos los datos para test y para entrenamiento (20% test y 80% entrenamiento)
# test_size indica el % usado para el test (0.2/1 = 20%)
# random_state es una semilla de aleatoreidad, ponemos una para que sea
# siempre la misma división de datos.

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)


# Como criterio he elegido Gini
# Como la DB es pequeña, podemos permitirnos en teoría que splitter sea 'best'
# He puesto un max_depth de 15 para que no haya sobrecorrección y además computacionalmente cueste menos
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
plot_tree(modelo, filled=True, feature_names=x.columns, class_names=["yes", "no"])  # Ajusta las clases según tu dataset
plt.show()


#Visualizar el árbol en texto
arbol_texto = export_text(modelo, feature_names=list(x.columns))
print(arbol_texto)
