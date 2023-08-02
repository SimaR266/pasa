import logging
from flask import Flask
from telegram.ext import Updater, CommandHandler
import os

# Flask uygulamasını başlatın
app = Flask(__name__)

# Botun başlamasını sağlayan komut işleyicisi
def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Merhaba!")

# Botun size "merhaba" demesine izin veren komut işleyicisi
def hello(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Selam!")

def main():
    # Telegram botunuzun tokenini burada belirtin
    token = '5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ'
    updater = Updater(token=token, use_context=True)

    dispatcher = updater.dispatcher
    
    # "/start" komutuna başlama işlevini atayın
    start_handler = CommandHandler('start', start)
    dispatcher.add_handler(start_handler)
    
    # "/hello" komutuna "hello" işlevini atayın
    hello_handler = CommandHandler('hello', hello)
    dispatcher.add_handler(hello_handler)

    # Botu başlatın
    port = int(os.environ.get("PORT", 10000))  # Portu alın veya varsayılan olarak 5000 kullanın
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)  # Günlüğü yapılandırın
    main()