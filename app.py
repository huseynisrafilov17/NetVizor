import asyncio
from flask import Flask, render_template, request, jsonify
from netVizor import scan_single_ip_async, scan_network_async

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/tool')
def tool():
    return render_template('tool.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form['ip']
    results = asyncio.run(scan_single_ip_async(ip))
    return jsonify(results)

@app.route('/scan_network', methods=['POST'])
def scan_network_route():
    subnet = request.form['subnet']
    results = asyncio.run(scan_network_async(subnet))
    return jsonify(results)

if __name__ == '__main__':
    try:
        print("1. Terminal app")
        print("2. Web app")
        user_choice = int(input("Please make a choice (e.g 1): "))
        print()
        match user_choice:
            case 1:
                print("1. Host scan")
                print("2. Subnet scan")
                scan_choice = int(input("Please make a choice (e.g 1): "))
                print()
                match scan_choice:
                    case 1:
                        ip = input("Please enter an IPv4 address: ")
                        results = asyncio.run(scan_single_ip_async(ip))
                        print()
                        for key, value in results.items():
                            if isinstance(value, list):
                                print(f"{key.replace("_", " ").capitalize()}: {', '.join(list(map(lambda x: str(x), value)))}")
                            else:
                                print(f"{key.replace("_", " ").capitalize()}: {value}")
                    case 2:
                        subnet = input("Please enter a Subnet (e.g., 192.168.1.0/24): ")
                        results = asyncio.run(scan_network_async(subnet))
                        for dictionary in results.values():
                            print()
                            for key, value in dictionary.items():
                                if isinstance(value, list):
                                    print(f"{key.replace("_", " ").capitalize()}: {', '.join(list(map(lambda x: str(x), value)))}")
                                else:
                                    print(f"{key.replace("_", " ").capitalize()}: {value}")
                    case _:
                        print("Wrong input.")
            case 2:
                app.run(host='0.0.0.0')
            case _:
                print("Wrong input.")
    except Exception as e:
        print(f"Wrong input. {e}")
