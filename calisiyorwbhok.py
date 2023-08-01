
import telepot
import webbrowser
import requests
from flask import Flask, request
from telegram.ext import Updater, CommandHandler
import logging
from telegram import Update
from telegram import Bot
import urllib3
server-app.server

proxy_url = "http://8.209.114.72:3129"
telepot.api._pools = {
    'default': urllib3.ProxyManager(
        proxy_url=proxy_url,
        num_pools=3,
        maxsize=10,
        retries=False,
        timeout=30
    )
}
secret = "c04a4385-a7e2-4bf5-b8ab-d7599109d1d1"
bot_token = "5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ"

bot = Bot(bot_token)
app = Flask(__name__)

# Kameraları listeleme fonksiyonu eklenebilir

def start_handler(update: Update, context):
    message = "Bot devrede!"
    chat_id = update.effective_chat.id
    bot.send_message(chat_id=chat_id, text=message)

def yan_handler(update, context):
    url = ' '.join(context.args)
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        response = requests.get(url)

        if response.status_code == 200:
            message = f"✅ Bağlantı Başarılı!\n\nURL: {url}"

            # Stream URL'i ise expired_date bilgisini gösterelim
            if "stream" in url:
                stream_info = get_stream_info(url)
                if stream_info is not None:
                    message += f"\nBitiş tarihi: {stream_info['expired_date']}"
                
            context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="URL pasif!")

    except requests.exceptions.RequestException as e:
        context.bot.send_message(chat_id=update.effective_chat.id, text="🚦 URL geçerli değil!")

def get_stream_info(url):
    # İlgili stream linkini kontrol etmek için ek kodu buraya ekleyebilirsiniz
    return {
        'expired_date': '31 Temmuz 2023'  # Örnek bir bitiş tarihi
    }

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

bot.setWebhook("https://Simar26.pythonanywhere.com/{}".format(secret))

if __name__ == '__main__':
    app.run(debug=True)
