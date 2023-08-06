
import telegram
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext

# Telegram botunuzun token'ını buraya girin
TOKEN = '5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ'

def start(update: Update, context: CallbackContext):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Merhaba!")

def main():
    # Telegram botunuzun updater nesnesini oluşturun
    updater = Updater(token=TOKEN, use_context=True)
    dispatcher = updater.dispatcher
    
    # Botunuza "/start" komutuna yanıt verecek bir işleyici ekleyin
    start_handler = CommandHandler('start', start)
    dispatcher.add_handler(start_handler)
    
    # Webhook URL'nizi buraya yapıştırın
    WEBHOOK_URL = 'https://api.render.com/deploy/srv-cj4af02ip7vuask3tcfg?key=qiWPDsXBCuc'
    
    # Botunuza web hook adresini ayarlayın
    updater.start_webhook(listen="0.0.0.0", port=8443, url_path=TOKEN)
    updater.bot.set_webhook(url=WEBHOOK_URL + '/' + TOKEN)
    
    # Botu başlatın
    updater.idle()

if __name__ == '__main__':
    main()
