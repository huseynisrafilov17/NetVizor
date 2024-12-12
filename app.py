from flask import Flask, render_template, request, jsonify
from netVizor import scan_single_ip, scan_network
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form['ip']
    results = scan_single_ip(ip)
    return jsonify(results)

@app.route('/scan_network', methods=['POST'])
def scan_network_route():
    subnet = request.form['subnet']
    results = scan_network(subnet)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
