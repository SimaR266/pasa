
import logging
from flask import Flask, request
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

# Flask uygulamasını başlatın
app = Flask(__name__)

# Telegram bot token'ınızı buraya girin
BOT_TOKEN = "5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ"
updater = Updater(BOT_TOKEN, use_context=True)
dispatcher = updater.dispatcher

# /start komutunu işleyen fonksiyon
def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Bot açık")

start_handler = CommandHandler('start', start)
dispatcher.add_handler(start_handler)

# Mesajları işleyen fonksiyon
def handle_message(update, context):
    message_text = update.message.text
    if message_text.lower() == "merhaba":
        context.bot.send_message(chat_id=update.effective_chat.id, text="Selam")

message_handler = MessageHandler(Filters.text & (~Filters.command), handle_message)
dispatcher.add_handler(message_handler)

# Flask HTTP webhook'u etkinleştirme
@app.route('https://pasa-yol.onrender.com/', methods=['POST'])
def webhook():
    update = telegram.Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return 'ok'

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # Flask uygulamanızı gunicorn ile çalıştırın
    app.run(host='0.0.0.0', port=8080)
