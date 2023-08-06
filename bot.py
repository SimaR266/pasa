import telebot
import requests
import json
from telebot import types
from flask import Flask, request
import os
from datetime import datetime
import traceback

TOKEN =  os.environ['TOKEN']
WEBHOOK = os.environ['WEBHOOK']
bot = telebot.TeleBot(TOKEN)
server = Flask(__name__)
bot = Bot(bot_token)
app = Flask(__name__)

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
            if 'server_info' in resp:
                url_server = resp['server_info'].get('url', '')
                port_server = resp['server_info'].get('port', '')
                client_area = f"http://{url_server}:{port_server}/client_area/index.php?username={username}&password={password}&submit"

            if expirate:
                mensaje = f"Esta es la información de tu lista ⬇️\n\n🟢 Estado: {status}\n👤 Usuario: {username}\n🔑 Contraseña: {password}\n📅 Fecha de Caducidad: {expire_day}-{expire_month}-{expire_year}\n📅 Fecha de Creación: {create_day}-{create_month}-{create_year}\n👥 Conexiones activas: {a_connections}\n👥 Conexiones máximas: {m_connections}\n🔢 Número de Canales: {numero_streams}\n🖥️ Servidor: {url_server}:{port_server}\n🔒 Zona de Cliente: {client_area}\n\n🤖: @iptv_checker_bot\nDeveloped by Adrian Paniagua"
            else:
                mensaje = f"Esta es la información de tu lista ⬇️\n\n🟢 Estado: {status}\n👤 Usuario: {username}\n🔑 Contraseña: {password}\n📅 Fecha de Caducidad: Nunca\n📅 Fecha de Creación: {create_day}-{create_month}-{create_year}\n👥 Conexiones activas: {a_connections}\n👥 Conexiones máximas: {m_connections}\n🔢 Número de Canales: {numero_streams}\n🖥️ Servidor: {url_server}:{port_server}\n🔒 Zona de Cliente: {client_area}\n\n🤖: @iptv_checker_bot\nDeveloped by Adrian Paniagua"
        else:
            mensaje = "No he podido obtener la información de este enlace. Prueba con otro"

    except Exception:
        mensaje = "No he podido obtener la información de este enlace. Prueba con otro"
        traceback.print_exc()
        
    bot.reply_to(message, mensaje)

@server.route('/' + TOKEN, methods=['POST'])
def getMessage():
    bot.process_new_updates([telebot.types.Update.de_json(request.stream.read().decode("utf-8"))])
    return "!", 200

@server.route("/")
def webhook():
    bot.remove_webhook()
    bot.set_webhook(url=WEBHOOK + TOKEN)
    return "!", 200

if __name__ == "__main__":
      app.run(debug=True)
