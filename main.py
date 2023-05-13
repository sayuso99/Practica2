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

@app.route("/index.html")
def index():
    return render_template("index.html")

if __name__ == '__main__':
   app.run(debug = True)
