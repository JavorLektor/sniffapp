from flask import Flask, render_template, jsonify
from scapy.all import sniff

app = Flask(__name__)

# Global variable to store the last sniffed packet
last_packet = None

def packet_callback(packet):
    """Callback function to process each packet."""
    global last_packet
    last_packet = packet.summary()

@app.route('/')
def index():
    """Render the main page with a button."""
    return render_template('index.html')

@app.route('/sniff_packet', methods=['POST'])
def sniff_packet():
    """Sniff a single packet and return its summary."""
    global last_packet
    # Sniff a single packet using Scapy
    sniff(count=1, prn=packet_callback, timeout=5)  # timeout is optional

    # Return the packet summary to the frontend
    if last_packet:
        # Use `show(dump=True)` to capture the full packet details as a string
        report = last_packet.show(dump=True)
        return jsonify({'packet_summary': report})
    else:
        return jsonify({'packet_summary': 'No packet captured'})

if __name__ == '__main__':
    app.run(debug=True)
