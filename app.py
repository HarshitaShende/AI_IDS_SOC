from flask import Flask, render_template, request, send_file, jsonify
import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import os, sqlite3

app = Flask(__name__)

model = joblib.load("ids_model.pkl")
encoder = joblib.load("attack_encoder.pkl")

risk_map = {
    "Normal": ("Safe",0),
    "Probe": ("Low",30),
    "WebAttack": ("Medium",55),
    "R2L": ("High",70),
    "DoS": ("Very High",85),
    "U2R": ("Critical",95)
}

BLACKLIST_FILE = "blacklist.txt"
REPORT_FOLDER = "reports"
STREAM_FILE = "traffic_stream.csv"
os.makedirs(REPORT_FOLDER, exist_ok=True)

stream_index = 0

def init_db():
    conn = sqlite3.connect("threat_history.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS threats(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, attack_type TEXT, risk TEXT, score INT)")
    c.execute("CREATE TABLE IF NOT EXISTS live_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, attack TEXT)")
    conn.commit()
    conn.close()
init_db()

def auto_block(ip="Simulated_IP"):
    open(BLACKLIST_FILE,"a").write(ip+"\n")

def log_stream(attack):
    conn = sqlite3.connect("threat_history.db")
    conn.cursor().execute("INSERT INTO live_logs VALUES(NULL,?,?)",(str(datetime.now()),attack))
    conn.commit(); conn.close()

def log_threat(a,r,s):
    conn = sqlite3.connect("threat_history.db")
    conn.cursor().execute("INSERT INTO threats VALUES(NULL,?,?,?,?)",(str(datetime.now()),a,r,s))
    conn.commit(); conn.close()

def generate_report(a,r,s):
    fn=f"{REPORT_FOLDER}/incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    c=canvas.Canvas(fn,pagesize=letter)
    c.drawString(100,750,"AI IDS Incident Report")
    c.drawString(100,720,f"Attack: {a}")
    c.drawString(100,700,f"Risk: {r}")
    c.drawString(100,680,f"Score: {s}/100")
    c.save()
    return fn

def preprocess(df):
    for col in ["protocol_type","service","flag"]:
        if col in df.columns:
            df = pd.get_dummies(df, columns=[col])
    return df.reindex(columns=model.feature_names_in_, fill_value=0)

@app.route("/")
@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html")

@app.route("/analyzer",methods=["GET","POST"])
def analyzer():
    prediction=risk=score=explain_img=report_file=None; prob_data=None
    if request.method=="POST":
        df=preprocess(pd.read_csv(request.files["file"]))
        pred=model.predict(df); proba=model.predict_proba(df)[0]
        prediction=encoder.inverse_transform(pred)[0]
        risk,score=risk_map[prediction]; prob_data=list(zip(encoder.classes_,proba))
        explainer=shap.TreeExplainer(model); shap_values=explainer.shap_values(df)
        plt.figure(); shap.summary_plot(shap_values,df,show=False)
        plt.savefig("static/shap.png",bbox_inches="tight"); plt.close(); explain_img="shap.png"
        if prediction!="Normal":
            auto_block(); report_file=generate_report(prediction,risk,score); log_threat(prediction,risk,score)
    return render_template("analyzer.html",prediction=prediction,risk=risk,score=score,explain_img=explain_img,report_file=report_file,prob_data=prob_data)

@app.route("/start_monitor")
def start_monitor(): global stream_index; stream_index=0; return "Started"

@app.route("/stream_predict")
def stream_predict():
    global stream_index
    df=pd.read_csv(STREAM_FILE)
    if stream_index>=len(df): stream_index=0
    row=preprocess(df.iloc[[stream_index]]); stream_index+=1
    pred=model.predict(row); attack=encoder.inverse_transform(pred)[0]; risk,score=risk_map[attack]
    log_stream(attack)
    if attack!="Normal": auto_block(); generate_report(attack,risk,score); log_threat(attack,risk,score)
    return jsonify({"attack":attack,"risk":risk,"score":score})

@app.route("/get_logs")
def get_logs():
    conn=sqlite3.connect("threat_history.db")
    logs=conn.cursor().execute("SELECT time,attack FROM live_logs ORDER BY id DESC LIMIT 15").fetchall()
    conn.close(); return jsonify(logs)

@app.route("/reports")
def reports(): return render_template("reports.html",reports=os.listdir(REPORT_FOLDER))

@app.route("/download/<f>")
def download(f): return send_file(f"{REPORT_FOLDER}/{f}",as_attachment=True)

@app.route("/research")
def research():
    return render_template("research.html")

if __name__=="__main__":
    app.run(debug=True)
