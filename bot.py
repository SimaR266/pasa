from flask import Flask, request
import telegram

app = Flask(__name__)
bot = telegram.Bot(token='5761864354:AAGbpgsIe3Nyp-FzRDylpkzN3lMXCS283SQ')

@app.route('https://api.render.com/deploy/srv-cj4af02ip7vuask3tcfg?key=qiWPDsXBCuc', methods=['POST'])
def webhook():
    if request.method == 'POST':
        update = telegram.Update.de_json(request.get_json(force=True), bot)
        chat_id = update.message.chat_id
        text = update.message.text

        # Eğer gelen mesaj "merhaba" ise "selam" cevabını veriyoruz
        if text.lower() == 'merhaba':
            bot.sendMessage(chat_id=chat_id, text='Selam!')

        return 'ok'

if __name__ == '__main__':
    # Flask uygulamasını çalıştırırken webhook URL'sini uygulamanızın URL'si olarak ayarlayın
    app.run(threaded=True)
