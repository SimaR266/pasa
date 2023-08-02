
import logging
import os
from flask import Flask
from telegram.ext import Updater, CommandHandler

app = Flask(__name__)

def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Merhaba!")

def hello(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Selam!")

def main():
    token = 'YOUR_TELEGRAM_BOT_TOKEN'
    updater = Updater(token=token, use_context=True)
    dispatcher = updater.dispatcher
    start_handler = CommandHandler('start', start)
    dispatcher.add_handler(start_handler)
    hello_handler = CommandHandler('hello', hello)
    dispatcher.add_handler(hello_handler)

    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
