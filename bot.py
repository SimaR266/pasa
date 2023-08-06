from flask import Flask, request
import requests

app = Flask(__name__)

def send_message(chat_id, text):
    token = '5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ'
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    data = {'chat_id': chat_id, 'text': text}
    response = requests.post(url, json=data)
    return response.json()

@app.route('https://api.render.com/deploy/srv-cj4af02ip7vuask3tcfg?key=qiWPDsXBCuc', methods=['POST'])
def webhook():
    if request.method == 'POST':
        update = request.get_json()
        chat_id = update['message']['chat']['id']
        text = update['message']['text']

        if text.lower() == 'merhaba':
            send_message(chat_id, 'Selam!')

        return 'ok'

if __name__ == '__main__':
    app.run(threaded=True)
