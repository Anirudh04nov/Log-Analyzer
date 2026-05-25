from flask import Flask, render_template, request, send_file
import os
from analyzer import analyze_log

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/", methods=["GET", "POST"])
def index():
    alerts = []
    top_attackers = []
    timeline = []
    total_ips = 0
    top_risky_ips = []
    graph_exists = False

    if request.method == "POST":
        file = request.files["logfile"]

        if file:
            path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(path)

            alerts, top_attackers, timeline, total_ips, top_risky_ips = analyze_log(path)

            if os.path.exists("static/graph.png"):
                graph_exists = True

    return render_template(
        "index.html",
        alerts=alerts,
        top_attackers=top_attackers,
        timeline=timeline,
        total_ips=total_ips,
        top_risky_ips=top_risky_ips,
        graph=graph_exists
    )

@app.route("/download")
def download():
    return send_file("report.txt", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)