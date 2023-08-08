import requests
from flask import Flask, request
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import CallbackContext, Filters, MessageHandler, Updater

app = Flask(__name__)
TELEGRAM_API_TOKEN = '6645176714:AAFL8GakKy37Tfqo4M_M2NF0085Z-hU8MEM'

def is_m3u_link(url):
    # Burada isterseniz M3U linkini kontrol edebilirsiniz
    # Örneğin, requests.get() kullanarak bağlantının çekilebilirliğini kontrol edebilirsiniz
    # Sadece örnekte M3U formatına uygun olduğunu varsayıyoruz
    # Eğer link geçerli ise True, değilse False döndürürüz
    return True

def start(update: Update, context: CallbackContext):
    update.message.reply_text("Merhaba! M3U bağlantısı gönderdiğinizde sınamak için 'M3U Link Kontrol Et' butonuna basabilirsiniz.")

def handle_message(update: Update, context: CallbackContext):
    message_text = update.message.text
    message_entities = update.message.entities

    if message_entities and message_entities[0].type == "url":
        url = message_text
        keyboard = [[InlineKeyboardButton("M3U Link Kontrol Et", callback_data=url)]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        update.message.reply_text("Bağlantının durumunu öğrenmek için aşağıdaki butona basın.", reply_markup=reply_markup)
    else:
        update.message.reply_text("Lütfen bir M3U bağlantısı gönderin.")

def handle_button_click(update: Update, context: CallbackContext):
    callback_data = update.callback_query.data
    is_active = is_m3u_link(callback_data)
    
    if is_active:
        update.callback_query.message.reply_text("Bağlantı aktif!")
    else:
        update.callback_query.message.reply_text("Bağlantı pasif!")

@app.route('/https://pasa-yol.onrender.com', methods=['POST'])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dp.process_update(update)
    return 'ok'

if __name__ == '__main__':
    bot = Updater(TELEGRAM_API_TOKEN, use_context=True)
    dp = bot.dispatcher
    dp.add_handler(MessageHandler(Filters.text, handle_message))
    dp.add_handler(CallbackQueryHandler(handle_button_click))
    dp.add_handler(CommandHandler('start', start))
    app.run(port=8000)
    bot.start_polling()
    bot.idle()
