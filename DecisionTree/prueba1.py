from re import DEBUG
from ucimlrepo import fetch_ucirepo 
from sklearn.model_selection import train_test_split 
from sklearn.tree import DecisionTreeClassifier

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


# Separamos los datos para test y para entrenamiento (20% test y 80% entrenamiento)
# test_size indica el % usado para el test (0.2/1 = 20%)
# random_state es una semilla de aleatoreidad, ponemos una para que sea
# siempre la misma división de datos.

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)


# Como criterio he elegido Gini
# Como la DB es pequeña, podemos permitirnos en teoría que splitter sea 'best'
# He puesto un max_depth de 15 para que no haya sobrecorrección y además computacionalmente cueste menos
# Uso el mismo random_state que antes, al poner un random_state en teoría disminuyo la aleatoreidad entre repeticiones del mismo test

modelo = DecisionTreeClassifier(criterion='gini', splitter='best', max_depth=15, random_state=42)

# construir el árbol
modelo.fit(x_train, y_train)

# Aunque para el TFG no es necesario es interesante ver si con esta
# configuración se obtendría una exactitud más o menos decente
exactitud = modelo.score(x_test, y_test)
