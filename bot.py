from flask import Flask, request
import requests
import json

app = Flask(__name__)

def send_message(chat_id, text):
    token = "5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    headers = {'Content-Type': 'application/json'}
    data = {'chat_id': chat_id, 'text': text}
    response = requests.post(url, headers=headers, json=data)
    return response.json()

@app.route('/https://pasa-yol.onrender.com', methods=['POST'])
def webhook():
    if request.method == 'POST':
        update = request.get_json()
        chat_id = update['message']['chat']['id']
        text = update['message']['text']

        if text.lower() == 'merhaba':
            send_message(chat_id, 'Selam!')

        return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
