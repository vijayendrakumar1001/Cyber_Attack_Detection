from flask import Flask, request, jsonify, render_template
import numpy as np
import joblib
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder
from flask_cors import CORS
import sqlite3 

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('front.html') 

# Load the trained model and scaler
model = tf.keras.models.load_model('model.h5')  # Correct way to load a Keras model
scaler = joblib.load('scaler.joblib')  # Load the scaler

# Encoding categorical values
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

        # Convert to numeric values
        L4_SRC_PORT = int(L4_SRC_PORT)
        L4_DST_PORT = int(L4_DST_PORT)

        # Encode categorical variables
        protocol_list = PROTOCOL.split('+')
        L7_proto_list = L7_PROTO.split('+')

        protocol_sum = sum(protocol_encoder.transform([protocol])[0] for protocol in protocol_list)
        L7_proto_sum = sum(l7_proto_encoder.transform([proto])[0] for proto in L7_proto_list)

        TCP_FLAGS = tcp_flags_encoder.transform([TCP_FLAGS])[0]

        # Prepare input features
        input_features = np.array([[L4_SRC_PORT, L4_DST_PORT, TCP_FLAGS, protocol_sum, L7_proto_sum]])

        # Scale features (important step!)
        input_features = scaler.transform(input_features)

        # Predict
        prediction = model.predict(input_features)
        prediction_probability = float(prediction[0][0])  # Ensure it's a float

        # Convert to class label
        predicted_class = 1 if prediction_probability > 0.5 else 0

        return jsonify({
            'prediction': int(predicted_class),
            'prediction_probability': round(prediction_probability, 4),  # Keep it readable
            'protocol_combination_sum': f"Sum of Protocols: {protocol_sum} + {L7_proto_sum}"  
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Function to check if an IP is blocked
def check_ip_in_db(ip_address):
    """Check if an IP is present in the database"""
    conn = sqlite3.connect("network_security.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?", (ip_address,))
    result = cursor.fetchone()[0]
    conn.close()
    return result > 0  

@app.route('/check_ip', methods=['POST'])
def check_ip():
    try:
        data = request.get_json()
        ip_address = data.get("ip_address")

        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400

        is_blocked = check_ip_in_db(ip_address)
        return jsonify({"blocked": is_blocked})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
