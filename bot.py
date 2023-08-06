from flask import Flask, request
from telegram.ext import Updater, CommandHandler

app = Flask(__name__)
updater = Updater(token='5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ', use_context=True)
dispatcher = updater.dispatcher

@app.route('https://api.render.com/deploy/srv-cj4af02ip7vuask3tcfg?key=qiWPDsXBCuc', methods=['POST'])
def webhook():
    if request.method == 'POST':
        update = request.get_json()
        text = update['message']['text']
        chat_id = update['message']['chat']['id']

        if text.lower() == 'merhaba':
            context.bot.send_message(chat_id=chat_id, text='Selam!')

        return 'ok'

if __name__ == '__main__':
    updater.start_webhook(listen="0.0.0.0", port=PORT, url_path='YOUR_WEBHOOK_URL', webhook_url='https://YOUR_APP_URL/YOUR_WEBHOOK_URL')
    updater.bot.set_webhook('https://YOUR_APP_URL/YOUR_WEBHOOK_URL')
    app.run(threaded=True)
