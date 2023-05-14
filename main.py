from flask import Flask, render_template, request
from sklearn import tree
import requests
import json
import plotly.utils
import sqlite3
import pandas as pd
import plotly.graph_objects as go

def decisionTreeClassifier():
    print("Arbol de decision")

def linearRegression():
    print("Regresion lineal")

def randomForest():
    print("Bosque aleatorio")

app = Flask(__name__)

@app.route("/")
@app.route("/index.html")
def index():
    return render_template("/index.html")

@app.route("/ipProblematica.html", methods=["GET","POST"])
def ipProblematica():
    num = request.form.get('numIPs', default=7)
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    query = con.execute("SELECT ORIGIN, COUNT(*) AS num FROM ALERTS GROUP BY ORIGIN ORDER BY num DESC LIMIT (?);", (num,))
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['origin', 'num'])
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['origin'], y=df_problematic_ips['num'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group') # title_text="Top IPs problematicas", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphIpProblematicas = json.dumps(fig, cls=a)
    return render_template("/ipProblematica.html", graphIpProblematicas=graphIpProblematicas, numIPs=num)

@app.route("/dispositivosVulnerables.html", methods=["GET","POST"])
def dispositivosVulnerables():
    num = request.form.get('numDisp', default=7)
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    query = con.execute("SELECT IP, (SERVICES+VULNERABILITIES) AS secure FROM DEVICES ORDER BY secure DESC LIMIT (?);", (num,))
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['IP', 'secure'])
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['IP'], y=df_problematic_ips['secure'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group') #title_text="Top Dispositivos vulnerables", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphDispVulnerables = json.dumps(fig, cls=a)
    return render_template("/dispositivosVulnerables.html", graphDispVulnerables=graphDispVulnerables, numDisp=num)

@app.route("/dispositivosPeligrosos.html", methods=["GET","POST"])
def dispositivosPeligrosos():
    swi = request.form.get('swiMore', default="")
    df_ipProblematica = pd.DataFrame()
    con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
    if swi == "on":
        query = con.execute("SELECT ID, (SERVICES||'.0'/INSECURES) AS secure FROM DEVICES WHERE (SERVICES/INSECURES) >= 0.33;")
    else:
        query = con.execute("SELECT ID, (SERVICES||'.0'/INSECURES) AS secure FROM DEVICES WHERE (SERVICES/INSECURES) < 0.33;")
    data = query.fetchall()
    df_problematic_ips = pd.DataFrame(data, columns=['IP', 'secure'])
    fig = go.Figure(data=[
        go.Bar(x=df_problematic_ips['IP'], y=df_problematic_ips['secure'], marker_color='steelblue')
    ])
    fig.update_layout(barmode='group') #title_text="Top Dispositivos vulnerables", title_font_size=41,
    a = plotly.utils.PlotlyJSONEncoder
    graphDispPeligrosos = json.dumps(fig, cls=a)
    return render_template("/dispositivosPeligrosos.html", graphDispPeligrosos=graphDispPeligrosos, swiMore=swi)

@app.route("/10vulnerabilidades.html")
def vulnerabilidades():
    page = requests.get("https://cve.circl.lu/api/last")
    jsons = page.json()
    listaCve = []
    listaSum = []
    for i in range(0,10):
        listaCve += [jsons[i]['id']]
        listaSum += [jsons[i]['summary']]
    fig = go.Figure(data=[go.Table(
        columnwidth=[130, 1500],
        header=dict(values=['Vulnerabilidad','Descripcion'],
                    line_color='darkslategray',
                    fill_color='lightskyblue',
                    align='left'),
        cells=dict(values=[listaCve,listaSum],
                    line_color='darkslategray',
                    fill_color='lightcyan',
                    align='left'))])
    tablaTopVul = plotly.io.to_html(fig)
    return render_template("/10vulnerabilidades.html",tablaTopVul=tablaTopVul)

if __name__ == '__main__':
   app.run(debug = True)
