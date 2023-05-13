from flask import Flask, render_template, request
from sklearn import tree
import json
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

@app.route("/")
@app.route("/ipProblematica.html")
def ipProblematica():
    return render_template("/ipProblematica.html")

@app.route("/")
@app.route("/dispositivosVulnerables.html")
def dispositivosVulnerables():
    return render_template("/dispositivosVulnerables.html")

@app.route("/")
@app.route("/10vulnerabilidades.html")
def vulnerabilidades():
    return render_template("/10vulnerabilidades.html")

if __name__ == '__main__':
   app.run(debug = True)
