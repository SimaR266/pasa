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

@bot.message_handler(commands=["start"])
def start(message):
    cid = message.chat.id
    bot.send_message(cid, "Hola!\nEste bot te permitirá comprobar el estado de tus listas mediante la API de Xtream Codes.\nPara comprobar tu lista tan solo tienes que enviarme el enlace y yo te mostraré toda la información\n\nBot desarrollado por @APLEONI\nhttps://github.com/adrianpaniagualeon/iptv-checker")

@bot.message_handler(func=lambda message: True)
def echo_message(message):
    try:
        numero_streams = 0
        cid = message.chat.id
        url = message.text
        url = url.replace('get.php', 'panel_api.php')
        respuesta = requests.get(url)
        open('respuesta.json', 'wb').write(respuesta.content)
        f = open('respuesta.json')
        json_file = json.load(f)
        json_str = json.dumps(json_file)
        resp = json.loads(json_str)
        if 'user_info' in resp:
            username = resp['user_info'].get('username', '')
            password = resp['user_info'].get('password', '')
            status = resp['user_info'].get('status', '')
            expire_dates = resp['user_info'].get('exp_date', None)

            if expire_dates is not None:
                expire_date = datetime.fromtimestamp(int(expire_dates))
                expirate = True

                expire_year = expire_date.strftime("%Y")
                expire_month = expire_date.strftime("%m")
                expire_day = expire_date.strftime("%d")
            else:
                expirate = False

            creates_dates = resp['user_info'].get('created_at', '')
            create_date = datetime.fromtimestamp(int(creates_dates))
            create_year = create_date.strftime("%Y")
            create_month = create_date.strftime("%m")
            create_day = create_date.strftime("%d")

            a_connections = resp['user_info'].get('active_cons', '')
            m_connections = resp['user_info'].get('max_connections', '')

            if 'available_channels' in resp:
                for stream in resp['available_channels']:
                    numero_streams += 1

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
