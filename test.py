from flask import Flask, jsonify, render_template
import asyncio

app = Flask(__name__)

# Example scanned data
TOPOLOGY_DATA = {
    "nodes": [
        {"id": "Switch", "label": "Switch", "group": "switch"},
        {"id": "192.168.1.2", "label": "192.168.1.2\nHost1", "group": "host"},
        {"id": "192.168.1.3", "label": "192.168.1.3\nHost2", "group": "host"},
    ],
    "edges": [
        {"from": "Switch", "to": "192.168.1.2"},
        {"from": "Switch", "to": "192.168.1.3"},
    ]
}

@app.route("/")
def index():
    return render_template("tool.html")

@app.route("/api/topology")
def get_topology():
    return jsonify(TOPOLOGY_DATA)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
