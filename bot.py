import telebot
import requests,json
from telebot import types
from flask import Flask, request
import os
from datetime import datetime
import traceback


TOKEN =  os.environ['TOKEN']
WEBHOOK = os.environ['WEBHOOK']


bot = telebot.TeleBot(TOKEN)
server = Flask(__name__)

def start_handler(update: Update, context):
    message = "Bot devrede!"
    chat_id = update.effective_chat.id
    bot.send_message(chat_id=chat_id, text=message)

def yan_handler(update: Update, context):
    url = update.message.text.split()[1]
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    try:
        response = requests.get(url)
        if response.status_code == 200:
            message = f"Bağlantı Çalışıyor!\n\nKullanıcı Adı: <SENİN_KULLANICI_ADI>\nParola: <SENİN_PAROLA>"
        else:
            message = "URL pasif!"
    except requests.exceptions.RequestException as e:
        message = f"Hata oluştu: {str(e)}"

    chat_id = update.effective_chat.id
    bot.send_message(chat_id=chat_id, text=message)

@app.route('/{}'.format(secret), methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    try:
        updater.dispatcher.process_update(update)
    except Exception as e:
        print(f"Hata: {str(e)}")
    return 'ok'

updater = Updater(bot_token, use_context=True)
updater.dispatcher.add_handler(CommandHandler('start', start_handler))
updater.dispatcher.add_handler(CommandHandler('yan', yan_handler))

if __name__ == '__main__':
    app.run(debug=True)
