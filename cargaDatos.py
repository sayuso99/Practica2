import sqlite3
import json
import csv

con = sqlite3.connect('./sqlite-tools-win32-x86-3410000/PRACTICA1.db')
cursorObj = con.cursor()

# Devices
def sql_check_responsible(name):
    cursorObj.execute("SELECT name FROM RESPONSIBLES WHERE NAME = '"+ name +"'")
    return cursorObj.fetchone()

def sql_insert_responsibles(name, phone, rol):
    cursorObj.execute("INSERT INTO RESPONSIBLES VALUES ('" + name + "','" + str(phone) + "','" + rol + "') ")
    con.commit()

def sql_insert_devices(id, ip, localization, rtb_responsible, services, insecures, vulnerabilities):
    cursorObj.execute("INSERT INTO DEVICES VALUES ('" + str(id) + "','" + str(ip) + "','" + str(localization) + "','" + str(rtb_responsible) + "','" + str(services) + "','" + str(insecures) + "','" + str(vulnerabilities) + "') ")
    con.commit()

def sql_insert_devices_port(rtbDevice, port):
    cursorObj.execute("INSERT INTO PORTS_DEVICE VALUES ('" + rtbDevice + "','" + port + "') ")
    con.commit()

arch = open("./data/devices.json", "r")
lines = json.load(arch)

i = 0
while i < len(lines):
   responsable = lines[i]["responsable"]
   if not (sql_check_responsible(responsable["nombre"])):
      sql_insert_responsibles(responsable["nombre"],responsable["telefono"],responsable["rol"])
   sql_insert_devices(lines[i]["id"],lines[i]["ip"],lines[i]["localizacion"],responsable["nombre"],lines[i]["analisis"]["servicios"],lines[i]["analisis"]["servicios_inseguros"],lines[i]["analisis"]["vulnerabilidades_detectadas"])
   puertos = lines[i]["analisis"]["puertos_abiertos"]
   x = 0
   while x < len(puertos):
      sql_insert_devices_port(lines[i]["id"],puertos[x])
      x = x+1
   i = i+1

# Alerts
def sql_insert_alerts(dateTime, sid, message, classification, priority, protocol, origin, destination, port):
    cursorObj.execute("INSERT INTO ALERTS VALUES ('" + str(dateTime) + "','" + str(sid) + "','" + message + "','" + str(classification) + "','" + str(priority) + "','" + str(protocol) + "','" + str(origin) + "','" + str(destination) + "','" + str(port) + "') ")

arch = open("./data/alerts.csv", "r")
lines = csv.reader(arch, delimiter=",")

next(lines)
for line in lines:
    sql_insert_alerts(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7],line[8])
con.commit()

con.close()