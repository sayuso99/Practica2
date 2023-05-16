import base64

from flask import Flask, render_template, request, redirect, session
from sklearn.linear_model import LinearRegression
import requests
import json
import plotly.utils
import sqlite3
import pandas as pd
import plotly.graph_objects as go
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import plot_tree
from sklearn import tree
from sklearn.metrics import accuracy_score, r2_score

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

usuarios = [["admin", "pass"], ["user", "pass"]]
app.secret_key = "Key"


@app.route("/", methods=["GET", "POST"])
def inicio():
    if (request.method == "POST"):
        user = request.form.get('user')
        passwd = request.form.get('passwd')
        for i in range(len(usuarios)):
            if (usuarios[i][0] == user and usuarios[i][1] == passwd):
                session['user'] = user
                return redirect('index.html')
        return "Usuario o contraseña incorrectos"
    return render_template("login.html")


@app.route("/index.html")
def index():
    if not session.get("user"):
        return redirect("/")
    return render_template("/index.html")


@app.route("/logout.html")
def logout():
    session['user'] = None
    return render_template("login.html")


@app.route("/ipProblematica.html", methods=["GET", "POST"])
def ipProblematica():
    if not session.get("user"):
        return redirect("/")
    num = request.form.get('numIPs', default=7)
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    query = con.execute("SELECT ORIGIN, COUNT(*) AS num FROM ALERTS GROUP BY ORIGIN ORDER BY num DESC LIMIT (?);",
                        (num,))
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['origin', 'num'])
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['origin'], y=df_problematic_ips['num'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group')  # title_text="Top IPs problematicas", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphIpProblematicas = json.dumps(fig, cls=a)
    return render_template("/ipProblematica.html", graphIpProblematicas=graphIpProblematicas, numIPs=num)

@app.route("/ipDiarias.html", methods=["GET", "POST"])
def ipDiarias():
    if not session.get("user"):
        return redirect("/")
    date = request.form.get('date', default='2022-07-03')
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    query = con.execute("SELECT origin, COUNT(*) FROM ALERTS WHERE substr(dateTime, 1, 10) = (?) GROUP BY origin ORDER BY COUNT(*)",
                        (date,))
    data = query.fetchall()
    df_date_ips = pd.DataFrame(data, columns=['origin', 'num'])
    fig = go.Figure(data=[
        go.Bar(x=df_date_ips['origin'], y=df_date_ips['num'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group')  # title_text="Top IPs problematicas", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphIpDiarias = json.dumps(fig, cls=a)
    return render_template("/ipDiarias.html", graphIpDiarias=graphIpDiarias, date=date)


@app.route("/dispositivosVulnerables.html", methods=["GET", "POST"])
def dispositivosVulnerables():
    if not session.get("user"):
        return redirect("/")
    num = request.form.get('numDisp', default=7)
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    query = con.execute("SELECT IP, (SERVICES+VULNERABILITIES) AS secure FROM DEVICES ORDER BY secure DESC LIMIT (?);",
                        (num,))
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['IP', 'secure'])
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['IP'], y=df_problematic_ips['secure'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group')  # title_text="Top Dispositivos vulnerables", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphDispVulnerables = json.dumps(fig, cls=a)
    return render_template("/dispositivosVulnerables.html", graphDispVulnerables=graphDispVulnerables, numDisp=num)


@app.route("/dispositivosPeligrosos.html", methods=["GET", "POST"])
def dispositivosPeligrosos():
    if not session.get("user"):
        return redirect("/")
    swi = request.form.get('swiMore', default="")
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    if swi == "on":
        query = con.execute(
            "SELECT ID, CASE WHEN SERVICES = 0 THEN 0.0 ELSE (CAST(INSECURES AS FLOAT) / SERVICES) END AS secure FROM DEVICES WHERE CASE WHEN SERVICES = 0 THEN 0.0 ELSE (CAST(INSECURES AS FLOAT) / SERVICES) END >= 0.33;")
    else:
        query = con.execute(
            "SELECT ID, CASE WHEN SERVICES = 0 THEN 0.0 ELSE (CAST(INSECURES AS FLOAT) / SERVICES) END AS secure FROM DEVICES WHERE CASE WHEN SERVICES = 0 THEN 0.0 ELSE (CAST(INSECURES AS FLOAT) / SERVICES) END < 0.33;")
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['IP', 'secure'])
    df_problematic_ips['secure'] = df_problematic_ips["secure"].apply(lambda x: 0.005 if x == 0 else x)
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['IP'], y=df_problematic_ips['secure'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group')  # title_text="Top Dispositivos vulnerables", title_font_size=41,
    fig.update_yaxes(range=[0.0, max(df_problematic_ips['secure'])+1])
    a = plotly.utils.PlotlyJSONEncoder
    graphDispPeligrosos = json.dumps(fig, cls=a)
    return render_template("/dispositivosPeligrosos.html", graphDispPeligrosos=graphDispPeligrosos, swiMore=swi)


@app.route("/10vulnerabilidades.html")
def vulnerabilidades():
    if not session.get("user"):
        return redirect("/")
    page = requests.get("https://cve.circl.lu/api/last")
    jsons = page.json()
    listaCve = []
    listaSum = []
    for i in range(0, 10):
        listaCve += [jsons[i]['id']]
        listaSum += [jsons[i]['summary']]
    fig = go.Figure(data=[go.Table(
        columnwidth=[130, 1500],
        header=dict(values=['Vulnerabilidad', 'Descripcion'],
                    line_color='darkslategray',
                    fill_color='lightskyblue',
                    align='left'),
        cells=dict(values=[listaCve, listaSum],
                   line_color='darkslategray',
                   fill_color='lightcyan',
                   align='left'))])
    tablaTopVul = plotly.io.to_html(fig)
    return render_template("/10vulnerabilidades.html", tablaTopVul=tablaTopVul)


@app.route("/regresionLineal.html", methods=["GET", "POST"])
def RegLineal():
    if not session.get("user"):
        return redirect("/")

    json_entrenamiento = "data/devices_IA_clases.json"
    json_prueba = "data/devices_IA_predecir_v2.json"

    with open(json_entrenamiento, "r") as archivo_entrenamiento:
        datos_entrenamiento = json.load(archivo_entrenamiento)

    with open(json_prueba, "r") as archivo_prueba:
        datos_prueba = json.load(archivo_prueba)

    x = np.array([d["servicios"] for d in datos_prueba])
    y = np.array([d["servicios_inseguros"] for d in datos_prueba])
    etiquetas = []
    colores = []

    for d in datos_prueba:
        servicios = d["servicios"]
        servicios_inseguros = d["servicios_inseguros"]
        porcentaje_inseguros = servicios_inseguros / servicios

        if porcentaje_inseguros >= 0.33:
            etiquetas.append("Inseguros")
            colores.append("red")
        else:
            etiquetas.append("Seguros")
            colores.append("blue")

    # Realizar la regresion lineal
    regresion_lineal = LinearRegression()
    regresion_lineal.fit(x.reshape(-1, 1), y)

    # Calcular los puntos para trazar la linea de regresion
    x_line = np.array([min(x), max(x)]).reshape(-1, 1)
    y_line = regresion_lineal.predict(x_line)

    # Plotear los puntos y la linea de regresion
    plt.scatter(x, y, c=colores)
    plt.plot(x_line, y_line, color='black', linewidth=2)

    # Configuracion del grafico
    plt.xlabel('Servicios')
    plt.ylabel('Servicios Inseguros')
    plt.title('Regresión Lineal')
    plt.legend(['Peligroso', 'Recta de regresion'])
    plt.savefig("static/plot.png")
    plt.close()

    return render_template('/regresionLineal.html', graphLinealRegresion="static/plot.png")


@app.route("/arbolDecision.html", methods=["GET", "POST"])
def ArbolDecision():
    if not session.get("user"):
        return redirect("/")

    # Cargar los datos de entrenamiento y prueba
    json_entrenamiento = "data/devices_IA_clases.json"
    json_prueba = "data/devices_IA_predecir_v2.json"
    with open(json_entrenamiento, "r") as archivo_entrenamiento:
        datos_entrenamiento = json.load(archivo_entrenamiento)

    with open(json_prueba, "r") as archivo_prueba:
        datos_prueba = json.load(archivo_prueba)

    # Obtener las características (X) y las etiquetas (y) de entrenamiento
    X_train = np.array([d["servicios"] for d in datos_entrenamiento])
    y_train = np.array([d["peligroso"] for d in datos_entrenamiento])

    # Crear el modelo del árbol de decisión
    clf = tree.DecisionTreeClassifier(max_depth=3)
    clf.fit(X_train.reshape(-1, 1), y_train)

    # Generar el gráfico del árbol de decisión
    fig, ax = plt.subplots(figsize=(8, 4))
    plot = plot_tree(
        decision_tree=clf,
        feature_names=['Servicios'],
        class_names=['No Peligroso', 'Peligroso'],
        filled=True,
        impurity=False,
        fontsize=9,
        precision=4,
        ax=ax
    )
    plt.savefig("static/decision_tree.png")
    plt.close()

    return render_template('/arbolDecision.html', graphDecisionTree="static/decision_tree.png")


@app.route("/randomForest.html", methods=["GET", "POST"])
def RandomForest():
    if not session.get("user"):
        return redirect("/")
    json_entrenamiento = "data/devices_IA_clases.json"
    json_prueba = "data/devices_IA_predecir_v2.json"
    with open(json_entrenamiento, "r") as archivo_entrenamiento:
        datos_entrenamiento = json.load(archivo_entrenamiento)

    with open(json_prueba, "r") as archivo_prueba:
        datos_prueba = json.load(archivo_prueba)

    # Preparar los datos de entrenamiento y prueba
    x_train = np.array([d["servicios"] for d in datos_entrenamiento])
    y_train = np.array([(d["servicios_inseguros"] / d["servicios"]) >= 0.33 if d["servicios"] != 0 else False for d in
                        datos_entrenamiento])
    x_test = np.array([d["servicios"] for d in datos_prueba])
    y_test = np.array([(d["servicios_inseguros"] / d["servicios"]) >= 0.33 if d["servicios"] != 0 else False for d in
                       datos_prueba])

    # Creamos el modelo de Random Forest
    clf_model = RandomForestClassifier(max_depth=2, random_state=0, n_estimators=10)
    clf_model.fit(x_train.reshape(-1, 1), y_train)

    # Hacemos predicciones
    y_pred = clf_model.predict(x_test.reshape(-1, 1))
    peligrosos = sum(y_pred)
    no_peligrosos = len(y_pred) - peligrosos

    # Calculamos el accuracy
    accuracy = accuracy_score(y_test, y_pred)

    # Graficar los árboles del Random Forest
    graph_files = []
    for i, estimator in enumerate(clf_model.estimators_):
        fig, ax = plt.subplots(figsize=(12, 5))
        plot = plot_tree(
            decision_tree=estimator,
            feature_names=['Servicios'],
            class_names=['No peligroso', 'Peligroso'],
            filled=True,
            impurity=False,
            fontsize=9,
            precision=4,
            ax=ax
        )
        file_name = f"static/decisionTree_{i}.png"
        plt.savefig(file_name)
        plt.close(fig)
        graph_files.append(file_name)

    return render_template('/randomForest.html', graphRandomForest=graph_files)


if __name__ == '__main__':
    app.run(debug=True)
