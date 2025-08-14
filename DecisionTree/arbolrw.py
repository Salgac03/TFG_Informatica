from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, plot_tree, export_text
import matplotlib.pyplot as plt
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import os


# Transformamos los int de float a int de nuevo
def format_threshold(threshold):
    if threshold == float('inf'):
        return 'inf'
    if threshold == int(threshold):
        return str(int(threshold))
    return f"{threshold:.2f}"


# Transformamos las condidiones a condiciones válidas
def condiciones_validas(cond : str) -> str:
    '''
    Define reglas especiales para ciertos casos
    '''
    
    if cond == "src_port <= inf" or cond == "dst_port <= inf":
        return "ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP"

    if "protocolo_IP_TCP <=" in cond:
        return "ip_proto == 6"
    elif "protocolo_IP_TCP =" in cond: 
        return "ip_proto != 6"

    if "protocolo_IP_UDP <=" in cond:
        return "ip_proto == 17"
    elif "protocolo_IP_TCP =" in cond: 
        return "ip_proto != 17"

    if "ip_frag_flags_DF <=" in cond:
        return "ip_frag_flags != 2"
    elif "ip_frag_flags_DF >" in cond:
        return "ip_frag_flags == 2"

    if "ip_frag_flags_MF <=" in cond:
        return "ip_frag_flags != 1"
    elif "ip_frag_flags_MF >" in cond:
        return "ip_frag_flags == 1"

    if "ip_ttl" in cond:
        return f"{cond} && ip_ttl != 0"

    # Añadir más reglas si es necesario

    return cond

# Se recorre el árbol de manera recursiva el árbol y se va generando el código C
def generar_codigo_c(tree, feature_names, node=0, depth=3, feature_map=None):
    indent = "    " * depth

    if feature_map is None:
        feature_map = {name: name for name in feature_names}

    if tree.feature[node] != -2:
        nombre_feature = feature_map.get(feature_names[tree.feature[node]], feature_names[tree.feature[node]])
        threshold = format_threshold(tree.threshold[node])

        raw_cond = f"{nombre_feature} <= {threshold}"
        cond = condiciones_validas(raw_cond)
        codigo = f"{indent}if ({cond}) {{\n"
        codigo += generar_codigo_c(tree, feature_names, tree.children_left[node], depth + 1, feature_map)
        codigo += f"{indent}}} else {{ // {nombre_feature} > {threshold}\n"
        codigo += generar_codigo_c(tree, feature_names, tree.children_right[node], depth + 1, feature_map)
        codigo += f"{indent}}}\n"
        return codigo
    else:
        clase = tree.value[node].argmax()
        accion = "XDP_DROP" if clase == 1 else "XDP_PASS"
        return f"{indent}action = {accion}; // Clase predicha: {clase}\n"




def main():
    # Especifica la ruta del archivo CSV
    csv_file_path = '../dataset.csv'

    # Lista de columnas que NO quieres usar para el entrenamiento
    columnas_a_excluir = ["eth_src", "eth_dst",  "ip_src", "ip_dst", "timestamp"]

    # Cargar el CSV
    try:
        df = pd.read_csv(csv_file_path)
    except FileNotFoundError:
        print(f"Error: El archivo CSV no se encontró en la ruta: {csv_file_path}")
        exit()

    # Última columna es la clase objetivo
    nombre_columna_objetivo = df.columns[-1]
    y = df[nombre_columna_objetivo]

    # Columnas X sin las excluidas
    columnas_caracteristicas = [col for col in df.columns if col != nombre_columna_objetivo and col not in columnas_a_excluir]
    x = df[columnas_caracteristicas]
    x = pd.get_dummies(x)

    # División de datos
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

    # Entrenar el modelo
    modelo = DecisionTreeClassifier(criterion='gini', splitter='best', max_depth=4, random_state=42)
    modelo.fit(x_train, y_train)
    exactitud = modelo.score(x_test, y_test)
    print(f'La exactitud del modelo es: {exactitud: .2f}')

    # Mostrar el árbol
    plt.figure(figsize=(20, 10))
    plot_tree(modelo, filled=True, feature_names=x.columns, class_names=y.unique().astype(str))
    plt.show()

    # Exportar el árbol como texto
    arbol_texto = export_text(modelo, feature_names=list(x.columns))
    print(arbol_texto)

    feature_map = {
        "ip_ttl": "ip_ttl",
        "ip_proto": "ip_proto",
        "eth_type": "bpf_htons(eth_type)",
        # Agrega más si tu dataset tiene otras columnas relevantes
    }

    codigo_arbol_c = generar_codigo_c(modelo.tree_, x.columns.tolist(), feature_map=feature_map)

    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("./xdp_kern.j2")

    codigo_c = template.render(decision_tree=codigo_arbol_c)

    # Guardar a archivo .c
    with open("../XDP/arbol_prueba/xdp_kern.c", "w") as f:
        f.write(codigo_c)

    print("Archivo 'xdp_kern.c' generado con éxito en XDP/arbol_prueba.")



if __name__ == '__main__':
    main()
