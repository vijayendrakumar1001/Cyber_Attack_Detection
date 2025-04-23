from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from flask_cors import CORS
import sqlite3
import pandas as pd

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('front.html')

# Load model and scaler
model_data = joblib.load('model.joblib')
model = model_data['model']
scaler = model_data['scaler']

# Define encoders
tcp_flags_encoder = LabelEncoder()
protocol_encoder = LabelEncoder()
l7_proto_encoder = LabelEncoder()

tcp_flags_encoder.fit(["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "NS"])
protocol_encoder.fit(["TCP", "UDP", "ICMP", "IP", "SNMP", "SSL", "TLS", "IPsec"])
l7_proto_encoder.fit(["HTTP", "FTP", "DNS", "HTTPS", "SMTP", "IMAP", "POP3", "SSH"])

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        L4_SRC_PORT = data.get('L4_SRC_PORT')
        L4_DST_PORT = data.get('L4_DST_PORT')
        TCP_FLAGS = data.get('TCP_FLAGS')
        PROTOCOL = data.get('PROTOCOL')
        L7_PROTO = data.get('L7_PROTO')

        print(f"Received data: {data}")

        # Convert to integer
        L4_SRC_PORT = int(L4_SRC_PORT)
        L4_DST_PORT = int(L4_DST_PORT)

        # Encode protocol and L7 protocol safely
        protocol_list = PROTOCOL.split('+')
        L7_proto_list = L7_PROTO.split('+')

        try:
            protocol_sum = sum(protocol_encoder.transform([protocol])[0] for protocol in protocol_list)
        except ValueError:
            protocol_sum = -1  # Handle unknown protocols

        try:
            L7_proto_sum = sum(l7_proto_encoder.transform([proto])[0] for proto in L7_proto_list)
        except ValueError:
            L7_proto_sum = -1  # Handle unknown L7 protocols

        # Encode TCP_FLAGS safely
        try:
            TCP_FLAGS = tcp_flags_encoder.transform([TCP_FLAGS])[0]
        except ValueError:
            TCP_FLAGS = -1

        # Create input array
        input_features = np.array([[L4_SRC_PORT, L4_DST_PORT, TCP_FLAGS, protocol_sum, L7_proto_sum]])

        # Scale input
        input_features = scaler.transform(input_features)

        # Make prediction
        prediction = model.predict(input_features)
        predicted_class = int(prediction[0])  # Ensure integer response

        return jsonify({
            'prediction': predicted_class,
            'protocol_combination_sum': f"Sum of Protocols: {protocol_sum} + {L7_proto_sum}"
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

def check_ip_in_db(ip_address):
    """Check if an IP is present in the database"""
    conn = sqlite3.connect("network_security.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?", (ip_address,))
    result = cursor.fetchone()[0]
    conn.close()
    return result > 0  

ip_df = pd.read_csv("ips.csv") 
blocked_ips = set(ip_df["IP Address"].astype(str)) 
@app.route("/check_ip", methods=["POST"])
def check_ip():
    data = request.get_json()
    ip_address = data.get("ip_address", "").strip()

    if ip_address in blocked_ips:
        return jsonify({"blocked": True, "message": f"IP {ip_address} is BLOCKED 🚨"})
    else:
        return jsonify({"blocked": False, "message": f"IP {ip_address} is SAFE ✅"})
if __name__ == '__main__':
    app.run(debug=True)
