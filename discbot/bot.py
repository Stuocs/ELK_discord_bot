import os
import time
import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv
#import smtplib
#from email.mime.text import MIMEText
#from email.mime.multipart import MIMEMultipart
import logging
import ssl
import requests
import json
import subprocess
import re
from datetime import datetime, time as dt_time
import ipaddress
import json
import asyncio
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
#GMAIL_USER = os.getenv('GMAIL_USER')
#GMAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')  # App password for Gmail
#RECIPIENT_EMAIL = os.getenv('RECIPIENT_EMAIL')

# Definir ruta de log principal a monitorear
LOG_PATH = '/var/log/syslog'

# Definir rutas de logs adicionales para comandos específicos
LOG_PATHS = {
    'memory': '/var/log/syslog',  # Para logs de memoria
    'iptables': '/var/log/kern.log',  # Para logs de iptables
    'kern': '/var/log/kern.log',  # Para logs del kernel
    'logstash': '/var/log/logst.log',  # Para logs de logstash
    'nginx': '/var/log/nginx/error.log',  # Para logs de nginx
    'auth': '/var/log/auth.log',  # Para logs de autenticación
    'syslog': '/var/log/syslog',  # Para logs del sistema
    'postgresql': '/var/log/postgresql/postgresql-main.log',  # Para logs de PostgreSQL
    'apache': '/var/log/apache2/error.log',  # Para logs de Apache
    'mysql': '/var/log/mysql/error.log'  # Para logs de MySQL
}

# Configuraciones para filtrado de logs
BUSINESS_HOURS_START = dt_time(8, 0)  # 8:00 AM
BUSINESS_HOURS_END = dt_time(18, 0)   # 6:00 PM
INTERNAL_IP_RANGES = ['10.0.0.0/8', '192.168.0.0/16']
WHITELISTED_PROCESSES = ['systemd', 'cron', 'sshd', 'nginx', 'apache2', 'postgresql', 'mysql', 'filebeat', 'logstash', 'elasticsearch', 'kibana']
WHITELISTED_PORTS = [22, 80, 443, 3306, 5432, 9200, 9300, 5601, 5044]
CRITICAL_FILE_PATHS = ['/etc', '/var/log', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/boot', '/var/www', '/home']

# Patrones de búsqueda para logs específicos
LOG_PATTERNS = {
    'memory': ['memory', 'ram', 'swap', 'oom', 'out of memory'],
    'iptables': ['iptables', 'firewall', 'drop', 'reject', 'accept', 'forward'],
    'kern': ['kernel', 'module', 'firmware', 'hardware', 'cpu', 'io'],
    'logstash': ['logstash', 'pipeline', 'elasticsearch', 'index', 'filter'],
    'nginx': ['nginx', 'http', 'request', 'connection', '404', '500', '403'],
    'auth': ['authentication', 'login', 'password', 'sudo', 'su', 'user', 'group'],
    'postgresql': ['postgresql', 'database', 'query', 'transaction', 'deadlock'],
    'apache': ['apache', 'httpd', 'vhost', 'ssl', 'php'],
    'mysql': ['mysql', 'mariadb', 'query', 'innodb', 'connection']
}

# Número máximo de líneas a mostrar por comando
MAX_LINES = 20

# Initialize Discord bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

#ips_recientes
recent_ssh_ips = set()


# Function to send message via Discord API
async def send_discord_message(content):
    try:
        channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
        channel = bot.get_channel(channel_id)
        
        if channel is None:
            logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
            # Intentar buscar el canal en todos los servidores
            for guild in bot.guilds:
                for ch in guild.text_channels:
                    if ch.id == channel_id:
                        channel = ch
                        break
                if channel is not None:
                    break
        
        if channel:
            await channel.send(content)
            logger.info("Mensaje enviado a Discord vía API")
            return True
        else:
            logger.error(f"No se pudo encontrar el canal de Discord")
            return False
    except Exception as e:
        logger.error(f"Error enviando mensaje a Discord: {e}")
        return False

# Function to check if IP is internal
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in INTERNAL_IP_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        return False
    except:
        return False

# Function to check if time is outside business hours
def is_outside_business_hours(timestamp_str):
    try:
        # Parse timestamp (assuming ISO format)
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        current_time = dt.time()
        return current_time < BUSINESS_HOURS_START or current_time > BUSINESS_HOURS_END
    except:
        return False

# Function to format JSON for Discord
def format_json_for_discord(json_data):
    try:
        # Convertir a objeto Python si es una cadena
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
            
        # Formatear JSON con indentación para legibilidad
        formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
        
        # Dividir en chunks si es demasiado largo
        if len(formatted_json) > 1990:
            chunks = []
            current_chunk = ""
            for line in formatted_json.split('\n'):
                if len(current_chunk) + len(line) + 1 > 1990:
                    chunks.append(current_chunk)
                    current_chunk = line
                else:
                    if current_chunk:
                        current_chunk += '\n' + line
                    else:
                        current_chunk = line
            if current_chunk:
                chunks.append(current_chunk)
            
            return chunks
        else:
            return [formatted_json]
    except Exception as e:
        logger.error(f"Error formateando JSON: {e}")
        return [str(json_data)]

# Function to check if a log entry is important based on criteria
def is_important_log(log_entry):
    try:
        # Convertir a objeto Python si es una cadena
        if isinstance(log_entry, str):
            try:
                entry = json.loads(log_entry)
            except:
                # Si no es JSON válido, verificar si contiene palabras clave
                return any(keyword in log_entry.lower() for keyword in 
                          ['error', 'failed', 'exception', 'timeout', 'suspicious', 
                           'unauthorized', 'attack', 'failure', 'modify', 'escalate', 
                           'change', 'login', 'authentication'])
        else:
            entry = log_entry
        
        # 1. Errores del pipeline
        if entry.get('log', {}).get('level') == 'error':
            return True
        
        message = str(entry.get('message', '')).lower()
        if any(keyword in message for keyword in ['failed', 'exception', 'timeout']):
            return True
        
        # 2. Logs con event.outcome: failure
        if entry.get('event', {}).get('outcome') == 'failure':
            return True
        
        # 3. Logs con tags anómalos
        tags = entry.get('tags', [])
        if isinstance(tags, list) and any(tag in tags for tag in ['suspicious', 'unauthorized', 'attack']):
            return True
        
        # 4. Cambios de privilegios o configuraciones
        event_action = entry.get('event', {}).get('action', '')
        if event_action in ['modify', 'escalate', 'change']:
            return True
        
        # 5. Accesos denegados o fallidos
        if event_action in ['login', 'authentication'] and entry.get('event', {}).get('outcome') == 'failure':
            return True
        
        # 6. Actividades fuera de horario laboral
        timestamp = entry.get('@timestamp')
        if timestamp and is_outside_business_hours(timestamp):
            return True
        
        # 7. Procesos inusuales
        process_name = entry.get('process', {}).get('name')
        if process_name and process_name not in WHITELISTED_PROCESSES:
            return True
        
        # 8. IPs externas (no implementamos la frecuencia alta aquí, solo el chequeo de IP)
        source_ip = entry.get('source', {}).get('ip')
        if source_ip and not is_internal_ip(source_ip):
            return True
        
        # 9. Fallos en indexación
        es_status = entry.get('elasticsearch', {}).get('status')
        if es_status and (str(es_status).startswith('4') or str(es_status).startswith('5')):
            return True
        
        # 10. Eventos con user.name desconocido o inesperado
        # (Esto requeriría una lista de usuarios esperados, por ahora solo verificamos si existe)
        if 'user' in entry and 'name' in entry['user']:
            # Aquí podrías implementar una verificación contra una lista blanca
            pass
        
        # 11. Conexiones de red a puertos críticos o inusuales
        dest_port = entry.get('destination', {}).get('port')
        if dest_port and dest_port not in WHITELISTED_PORTS:
            return True
        
        # 12. Actividad relacionada con escaneo o automatización
        user_agent = str(entry.get('user_agent', {}).get('original', '')).lower()
        if 'scanner' in user_agent or 'bot' in user_agent or 'crawl' in user_agent:
            return True
        
        # 13. Logs con pipeline.failure
        if 'pipeline' in entry and 'failure' in entry['pipeline']:
            return True
        
        # 14. Cambios en archivos sensibles
        file_path = entry.get('file', {}).get('path', '')
        if file_path and any(file_path.startswith(critical_path) for critical_path in CRITICAL_FILE_PATHS):
            return True
        
        # 15. Reintentos múltiples (esto requeriría un seguimiento de eventos, no implementado aquí)
        
        return False
    except Exception as e:
        logger.error(f"Error evaluando importancia del log: {e}")
        return False

# Función para leer las últimas líneas de un archivo de log
def read_last_lines(file_path, num_lines=MAX_LINES, filter_pattern=None):
    try:
        if not os.path.exists(file_path):
            return f"⚠️ El archivo {file_path} no existe."
            
        # Usar subprocess para leer las últimas líneas de manera eficiente
        if filter_pattern:
            # Si hay un patrón de filtro, usar grep
            cmd = f"tail -n 1000 {file_path} | grep -i '{filter_pattern}' | tail -n {num_lines}"
        else:
            cmd = f"tail -n {num_lines} {file_path}"
            
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0 and result.returncode != 1:  # grep returns 1 if no matches
            logger.error(f"Error ejecutando comando: {cmd}, código: {result.returncode}")
            return f"Error leyendo archivo. Código: {result.returncode}"
        
        if not result.stdout.strip():
            return f"ℹ️ No se encontraron logs en {file_path}" + (f" con el patrón '{filter_pattern}'" if filter_pattern else "")
            
        return result.stdout
    except Exception as e:
        logger.error(f"Error leyendo archivo {file_path}: {e}")
        return f"❌ Error leyendo archivo {file_path}: {e}"


@tasks.loop(seconds=5)
async def monitor_ssh_connections():
    log_path = LOG_PATHS.get('iptables')
    if not os.path.exists(log_path):
        logger.warning(f"No se encontró el archivo de log: {log_path}")
        return

    result = read_last_lines(log_path, 100, filter_pattern='iptables')
    lines = result.strip().split('\n')

    for line in lines:
        if 'dpt:22' in line or 'DPT=22' in line or 'DSTPORT=22' in line:
            # Extraer IP fuente
            ip_match = re.search(r'(SRC=|src=)(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(2)
                if ip not in recent_ssh_ips:
                    recent_ssh_ips.add(ip)

                    msg = f"🚨 **Nueva conexión SSH detectada via IPTABLES**\nOrigen: `{ip}`\n```{line[:1900]}```"
                    await send_discord_message(msg)
                    logger.info(f"Alerta SSH enviada para IP {ip}")

@bot.event
async def on_ready():
    logger.info(f'{bot.user.name} has connected to Discord!')
    
    #Check if someone enters via ssh
    if not monitor_ssh_connections.is_running():
        monitor_ssh_connections.start()
        
    # Verificar que el canal existe
    channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
    channel = bot.get_channel(channel_id)
    
    if channel is None:
        logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
        # Intentar buscar el canal en todos los servidores
        for guild in bot.guilds:
            for ch in guild.text_channels:
                if ch.id == channel_id:
                    channel = ch
                    break
            if channel is not None:
                break
    
    if channel is None:
        logger.error(f"No se pudo encontrar el canal con ID {channel_id} en ningún servidor")
        # Enviar mensaje a cualquier canal al que tengamos acceso
        if len(bot.guilds) > 0 and len(bot.guilds[0].text_channels) > 0:
            await bot.guilds[0].text_channels[0].send("⚠️ **Error**: No se pudo encontrar el canal configurado. Por favor, verifica el ID del canal.")
    else:
        # Enviar mensaje de inicio
        await channel.send("🟢 **Bot iniciado correctamente!** Usa !help_logs para ver los comandos disponibles.")



@bot.command(name='status')
async def status(ctx):
    """Verificar si el bot está ejecutándose"""
    await ctx.send(f"✅ Bot en ejecución")

@bot.command(name='test')
async def test(ctx):
    """Enviar un log de prueba para verificar el funcionamiento"""
    try:
        test_log = {
            "@timestamp": datetime.now().isoformat(),
            "log": {"level": "error"},
            "message": "Este es un mensaje de prueba generado por el comando !test",
            "event": {"outcome": "failure"},
            "tags": ["test", "suspicious"],
            "source": {"ip": "8.8.8.8"},
            "user": {"name": "test_user"},
            "process": {"name": "test_process"}
        }
        
        # Enviar a Discord
        formatted_message = format_json_for_discord(test_log)
        await ctx.send(f"⚠️ **Alerta de Prueba**\n{formatted_message}")
        
        await ctx.send("✅ Log de prueba enviado correctamente")
    except Exception as e:
        await ctx.send(f"❌ Error enviando log de prueba: {e}")

import psutil

@bot.command(name='memory')
async def memory_logs(ctx):
    """Mostrar la memoria libre del sistema"""
    try:
        # Obtener la memoria libre
        memory_info = psutil.virtual_memory()
        free_memory = memory_info.available / (1024 ** 2)  # Convertir a MB
        await ctx.send(f"🖥️ Memoria libre del sistema: {free_memory:.2f} MB")
    except Exception as e:
        await ctx.send(f"❌ Error obteniendo la memoria libre: {e}")

@bot.command(name='iptables')
async def iptables_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs relacionados con iptables/firewall"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('iptables')
    patterns = '|'.join(LOG_PATTERNS.get('iptables', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔥 **Logs de firewall/iptables** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='kern')
async def kernel_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs del kernel"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('kern')
    patterns = '|'.join(LOG_PATTERNS.get('kern', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"💻 **Logs del kernel** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='log_paragraphs')
async def log_paragraphs(ctx, count: int = 5):
    """Mostrar N párrafos por cada palabra clave relevante"""
    if count > 50:
        await ctx.send("⚠️ Máximo 50 entradas por palabra clave.")
        count = 50

    log_path = LOG_PATHS.get('logstash')
    keywords = ['postgresql', 'system', 'iptables', 'nginx']

    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return

    await ctx.send(f"🔍 **Buscando {count} párrafos por palabra clave en {log_path}**")

    # Leer muchas líneas para encontrar suficientes ocurrencias
    raw_output = read_last_lines(log_path, 999999999, filter_pattern=None)
    lines_list = raw_output.strip().split('\n')

    matched_by_keyword = {kw: [] for kw in keywords}
    used_hashes = set()

    for line in lines_list:
        try:
            log_obj = json.loads(line)
            log_str = json.dumps(log_obj).lower()
            log_hash = hash(log_str)
        except json.JSONDecodeError:
            log_str = line.lower()
            log_obj = line
            log_hash = hash(log_str)

        if log_hash in used_hashes:
            continue

        for kw in keywords:
            if kw in log_str and len(matched_by_keyword[kw]) < count:
                if isinstance(log_obj, dict):
                    formatted = json.dumps(log_obj, indent=2, ensure_ascii=False)
                else:
                    formatted = log_obj
                matched_by_keyword[kw].append(formatted)
                used_hashes.add(log_hash)
                break  # para evitar que se repita en otro keyword

    total_found = sum(len(v) for v in matched_by_keyword.values())
    if total_found == 0:
        await ctx.send("ℹ️ No se encontraron párrafos relevantes.")
        return

    for kw in keywords:
        entries = matched_by_keyword[kw]
        if not entries:
            await ctx.send(f"🔎 **{kw}**: No se encontraron entradas.")
            continue

        await ctx.send(f"🔹 **{kw.upper()}** - {len(entries)} resultados:")
        for i, paragraph in enumerate(entries, 1):
            if len(paragraph) > 1990:
                chunks = [paragraph[j:j+1990] for j in range(0, len(paragraph), 1990)]
                await ctx.send(f"**{kw.upper()} - Entrada {i}/{len(entries)}**")
                for chunk in chunks:
                    await ctx.send(f"```json\n{chunk}\n```")
            else:
                await ctx.send(f"**{kw.upper()} - Entrada {i}/{len(entries)}**\n```json\n{paragraph}\n```")


@bot.command(name='nginx')
async def nginx_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de Nginx"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('nginx')
    patterns = '|'.join(LOG_PATTERNS.get('nginx', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🌐 **Logs de Nginx** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='auth')
async def auth_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de autenticación"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('auth')
    patterns = '|'.join(LOG_PATTERNS.get('auth', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔐 **Logs de autenticación** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='syslog')
async def syslog_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs del sistema"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('syslog')
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🖥️ **Logs del sistema** (últimas {lines} líneas):")
    result = read_last_lines(log_path, lines)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='postgresql')
async def postgresql_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de PostgreSQL"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('postgresql')
    patterns = '|'.join(LOG_PATTERNS.get('postgresql', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🐘 **Logs de PostgreSQL** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='apache')
async def apache_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de Apache"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('apache')
    patterns = '|'.join(LOG_PATTERNS.get('apache', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🌐 **Logs de Apache** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='mysql')
async def mysql_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de MySQL"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('mysql')
    patterns = '|'.join(LOG_PATTERNS.get('mysql', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🐬 **Logs de MySQL** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='help_logs')
async def help_logs(ctx):
    """Mostrar ayuda sobre los comandos de logs disponibles"""
    help_text = """📋 **Comandos de logs disponibles:**

!memory - Logs relacionados con la memoria del sistema
!iptables - Logs de firewall/iptables
!kern - Logs del kernel
!logstash - Logs de Logstash
!nginx - Logs de Nginx
!auth - Logs de autenticación
!syslog - Logs generales del sistema
!postgresql - Logs de PostgreSQL
!apache - Logs de Apache
!mysql - Logs de MySQL
!check_alerts [tipo_log] [líneas] - Revisar logs en busca de alertas importantes
!status - Verificar si el bot está ejecutándose
!test - Enviar un log de prueba
!help_logs - Mostrar esta ayuda

Puedes especificar el número de líneas a mostrar, por ejemplo: !nginx 50
(Máximo 100 líneas por razones de seguridad)"""
    
    await ctx.send(help_text)

# Run the bot
def main():
    try:
        # Iniciar el bot
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        logger.error(f"Error ejecutando el bot: {e}")
        print(f"Error al iniciar el bot: {e}")

async def send_discord_message(content):
    try:
        # Obtener el canal usando el ID del archivo .env
        channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
        channel = bot.get_channel(channel_id)
        
        if channel is None:
            logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
            return False
            
        # Enviar el mensaje directamente ya que estamos en un contexto async
        await channel.send(content)
        logger.info("Mensaje enviado a Discord vía canal")
        return True
    except Exception as e:
        logger.error(f"Error enviando mensaje a Discord vía canal: {e}")
        return False

def determine_alert_type(log_entry):
    """Determina el tipo de alerta basado en el contenido del log"""
    try:
        if isinstance(log_entry, str):
            try:
                entry = json.loads(log_entry)
            except:
                return "Log no estructurado"
        else:
            entry = log_entry
        
        if entry.get('raw_log', False):
            return "Log no estructurado"
        
        if entry.get('log', {}).get('level') == 'error':
            return "Error de Pipeline"
        
        if entry.get('event', {}).get('outcome') == 'failure':
            return "Fallo de Evento"
        
        tags = entry.get('tags', [])
        if isinstance(tags, list) and any(tag in tags for tag in ['suspicious', 'unauthorized', 'attack']):
            return "Actividad Sospechosa"
        
        event_action = entry.get('event', {}).get('action', '')
        if event_action in ['modify', 'escalate', 'change']:
            return "Cambio de Privilegios/Configuración"
        
        if event_action in ['login', 'authentication'] and entry.get('event', {}).get('outcome') == 'failure':
            return "Acceso Denegado"
        
        timestamp = entry.get('@timestamp')
        if timestamp and is_outside_business_hours(timestamp):
            return "Actividad Fuera de Horario"
        
        process_name = entry.get('process', {}).get('name')
        if process_name and process_name not in WHITELISTED_PROCESSES:
            return "Proceso Inusual"
        
        source_ip = entry.get('source', {}).get('ip')
        if source_ip and not is_internal_ip(source_ip):
            return "IP Externa"
        
        es_status = entry.get('elasticsearch', {}).get('status')
        if es_status and (str(es_status).startswith('4') or str(es_status).startswith('5')):
            return "Fallo de Indexación"
        
        dest_port = entry.get('destination', {}).get('port')
        if dest_port and dest_port not in WHITELISTED_PORTS:
            return "Puerto Inusual"
        
        if 'pipeline' in entry and 'failure' in entry['pipeline']:
            return "Fallo de Pipeline"
        
        file_path = entry.get('file', {}).get('path', '')
        if file_path and any(file_path.startswith(critical_path) for critical_path in CRITICAL_FILE_PATHS):
            return "Archivo Sensible Modificado"
        
        return "Alerta General"
    except Exception as e:
        logger.error(f"Error determinando tipo de alerta: {e}")
        return "Alerta No Clasificada"

@bot.command(name='check_alerts')
async def check_alerts(ctx, log_type='logstash', lines: int = 50):
    """Revisar logs en busca de alertas importantes"""
    if lines > 200:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden revisar más de 200 líneas a la vez.")
        lines = 200
    
    log_path = LOG_PATHS.get(log_type)
    if not log_path:
        await ctx.send(f"❌ Tipo de log no reconocido: {log_type}. Usa !help_logs para ver los tipos disponibles.")
        return
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔍 **Buscando alertas importantes en {log_type}** (últimas {lines} líneas)...")
    
    try:
        # Leer las últimas líneas del archivo
        result = read_last_lines(log_path, lines)
        lines_list = result.strip().split('\n')
        
        important_logs = []
        for line in lines_list:
            try:
                # Intentar parsear como JSON
                entry = json.loads(line.strip())
                
                # Verificar si el log es importante
                if is_important_log(entry):
                    # Determinar tipo de alerta
                    alert_type = determine_alert_type(entry)
                    formatted_json = json.dumps(entry, indent=2, ensure_ascii=False)
                    important_logs.append((alert_type, formatted_json))
            except json.JSONDecodeError:
                # No es un JSON válido, ignorar
                pass
            except Exception as e:
                logger.error(f"Error procesando línea de log: {e}")
        
        if not important_logs:
            await ctx.send("✅ No se encontraron alertas importantes en las líneas revisadas.")
            return
        
        await ctx.send(f"⚠️ **Se encontraron {len(important_logs)} alertas importantes:**")
        
        for i, (alert_type, log_json) in enumerate(important_logs, 1):
            # Dividir en chunks si es necesario
            if len(log_json) > 1990:
                chunks = [log_json[i:i+1990] for i in range(0, len(log_json), 1990)]
                await ctx.send(f"**Alerta {i}/{len(important_logs)} - Tipo: {alert_type}**")
                for chunk in chunks:
                    await ctx.send(f"```json\n{chunk}\n```")
            else:
                await ctx.send(f"**Alerta {i}/{len(important_logs)} - Tipo: {alert_type}**\n```json\n{log_json}\n```")
    
    except Exception as e:
        await ctx.send(f"❌ Error revisando logs: {e}")
        logger.error(f"Error en check_alerts: {e}")

if __name__ == "__main__":
    main()

# Modificar la función send_discord_webhook para usar el canal de Discord en lugar del webhook
async def send_discord_message(content):
    try:
        # Obtener el canal usando el ID del archivo .env
        channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
        channel = bot.get_channel(channel_id)
        
        if channel is None:
            logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
            return False
            
        # Enviar el mensaje directamente ya que estamos en un contexto async
        await channel.send(content)
        logger.info("Mensaje enviado a Discord vía canal")
        return True
    except Exception as e:
        logger.error(f"Error enviando mensaje a Discord vía canal: {e}")
        return False

# Reemplazar todas las llamadas a send_discord_webhook por send_discord_message
@bot.event
async def on_ready():
    logger.info(f'{bot.user.name} has connected to Discord!')
    
    # Verificar que el canal existe
    channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
    channel = bot.get_channel(channel_id)
    
    if channel is None:
        logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
        # Intentar buscar el canal en todos los servidores
        for guild in bot.guilds:
            for ch in guild.text_channels:
                if ch.id == channel_id:
                    channel = ch
                    break
            if channel is not None:
                break
    
    if channel is None:
        logger.error(f"No se pudo encontrar el canal con ID {channel_id} en ningún servidor")
        # Enviar mensaje a cualquier canal al que tengamos acceso
        if len(bot.guilds) > 0 and len(bot.guilds[0].text_channels) > 0:
            await bot.guilds[0].text_channels[0].send("⚠️ **Error**: No se pudo encontrar el canal configurado. Por favor, verifica el ID del canal.")
    else:
        # Enviar mensaje de inicio
        await channel.send("🟢 **Bot iniciado correctamente!** Usa !help_logs para ver los comandos disponibles.")



@bot.command(name='status')
async def status(ctx):
    """Verificar si el bot está ejecutándose"""
    await ctx.send(f"✅ Bot en ejecución")

@bot.command(name='test')
async def test(ctx):
    """Enviar un log de prueba para verificar el funcionamiento"""
    try:
        test_log = {
            "@timestamp": datetime.now().isoformat(),
            "log": {"level": "error"},
            "message": "Este es un mensaje de prueba generado por el comando !test",
            "event": {"outcome": "failure"},
            "tags": ["test", "suspicious"],
            "source": {"ip": "8.8.8.8"},
            "user": {"name": "test_user"},
            "process": {"name": "test_process"}
        }
        
        # Enviar a Discord
        formatted_message = format_json_for_discord(test_log)
        await ctx.send(f"⚠️ **Alerta de Prueba**\n{formatted_message}")
        
        await ctx.send("✅ Log de prueba enviado correctamente")
    except Exception as e:
        await ctx.send(f"❌ Error enviando log de prueba: {e}")

@bot.command(name='memory')
async def memory_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs relacionados con la memoria del sistema"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('memory')
    patterns = '|'.join(LOG_PATTERNS.get('memory', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"📊 **Logs de memoria** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='iptables')
async def iptables_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs relacionados con iptables/firewall"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('iptables')
    patterns = '|'.join(LOG_PATTERNS.get('iptables', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔥 **Logs de firewall/iptables** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='kern')
async def kernel_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs del kernel"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('kern')
    patterns = '|'.join(LOG_PATTERNS.get('kern', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"💻 **Logs del kernel** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='logstash')
async def logstash_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de Logstash"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('logstash')
    patterns = '|'.join(LOG_PATTERNS.get('logstash', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"📊 **Logs de Logstash** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='nginx')
async def nginx_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de Nginx"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('nginx')
    patterns = '|'.join(LOG_PATTERNS.get('nginx', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🌐 **Logs de Nginx** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='auth')
async def auth_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de autenticación"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('auth')
    patterns = '|'.join(LOG_PATTERNS.get('auth', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔐 **Logs de autenticación** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='syslog')
async def syslog_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs del sistema"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('syslog')
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🖥️ **Logs del sistema** (últimas {lines} líneas):")
    result = read_last_lines(log_path, lines)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='postgresql')
async def postgresql_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de PostgreSQL"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('postgresql')
    patterns = '|'.join(LOG_PATTERNS.get('postgresql', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🐘 **Logs de PostgreSQL** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='apache')
async def apache_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de Apache"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('apache')
    patterns = '|'.join(LOG_PATTERNS.get('apache', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🌐 **Logs de Apache** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='mysql')
async def mysql_logs(ctx, lines: int = MAX_LINES):
    """Mostrar logs de MySQL"""
    if lines > 100:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden mostrar más de 100 líneas a la vez.")
        lines = 100
    
    log_path = LOG_PATHS.get('mysql')
    patterns = '|'.join(LOG_PATTERNS.get('mysql', []))
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🐬 **Logs de MySQL** (últimas {lines} líneas que coinciden con el patrón):")
    result = read_last_lines(log_path, lines, patterns)
    
    # Dividir en chunks si es necesario
    if len(result) > 1990:
        chunks = [result[i:i+1990] for i in range(0, len(result), 1990)]
        for i, chunk in enumerate(chunks):
            await ctx.send(f"```{chunk}```")
    else:
        await ctx.send(f"```{result}```")

@bot.command(name='help_logs')
async def help_logs(ctx):
    """Mostrar ayuda sobre los comandos de logs disponibles"""
    help_text = """📋 **Comandos de logs disponibles:**

!memory - Logs relacionados con la memoria del sistema
!iptables - Logs de firewall/iptables
!kern - Logs del kernel
!logstash - Logs de Logstash
!nginx - Logs de Nginx
!auth - Logs de autenticación
!syslog - Logs generales del sistema
!postgresql - Logs de PostgreSQL
!apache - Logs de Apache
!mysql - Logs de MySQL
!check_alerts [tipo_log] [líneas] - Revisar logs en busca de alertas importantes
!status - Verificar si el bot está ejecutándose
!test - Enviar un log de prueba
!help_logs - Mostrar esta ayuda

Puedes especificar el número de líneas a mostrar, por ejemplo: !nginx 50
(Máximo 100 líneas por razones de seguridad)"""
    
    await ctx.send(help_text)

# Run the bot
def main():
    try:
        # Iniciar el bot
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        logger.error(f"Error ejecutando el bot: {e}")
        print(f"Error al iniciar el bot: {e}")

async def send_discord_message(content):
    try:
        # Obtener el canal usando el ID del archivo .env
        channel_id = int(os.getenv('DISCORD_CHANNEL_ID'))
        channel = bot.get_channel(channel_id)
        
        if channel is None:
            logger.warning(f"No se pudo encontrar el canal con ID {channel_id}")
            return False
            
        # Enviar el mensaje directamente ya que estamos en un contexto async
        await channel.send(content)
        logger.info("Mensaje enviado a Discord vía canal")
        return True
    except Exception as e:
        logger.error(f"Error enviando mensaje a Discord vía canal: {e}")
        return False

def determine_alert_type(log_entry):
    """Determina el tipo de alerta basado en el contenido del log"""
    try:
        if isinstance(log_entry, str):
            try:
                entry = json.loads(log_entry)
            except:
                return "Log no estructurado"
        else:
            entry = log_entry
        
        if entry.get('raw_log', False):
            return "Log no estructurado"
        
        if entry.get('log', {}).get('level') == 'error':
            return "Error de Pipeline"
        
        if entry.get('event', {}).get('outcome') == 'failure':
            return "Fallo de Evento"
        
        tags = entry.get('tags', [])
        if isinstance(tags, list) and any(tag in tags for tag in ['suspicious', 'unauthorized', 'attack']):
            return "Actividad Sospechosa"
        
        event_action = entry.get('event', {}).get('action', '')
        if event_action in ['modify', 'escalate', 'change']:
            return "Cambio de Privilegios/Configuración"
        
        if event_action in ['login', 'authentication'] and entry.get('event', {}).get('outcome') == 'failure':
            return "Acceso Denegado"
        
        timestamp = entry.get('@timestamp')
        if timestamp and is_outside_business_hours(timestamp):
            return "Actividad Fuera de Horario"
        
        process_name = entry.get('process', {}).get('name')
        if process_name and process_name not in WHITELISTED_PROCESSES:
            return "Proceso Inusual"
        
        source_ip = entry.get('source', {}).get('ip')
        if source_ip and not is_internal_ip(source_ip):
            return "IP Externa"
        
        es_status = entry.get('elasticsearch', {}).get('status')
        if es_status and (str(es_status).startswith('4') or str(es_status).startswith('5')):
            return "Fallo de Indexación"
        
        dest_port = entry.get('destination', {}).get('port')
        if dest_port and dest_port not in WHITELISTED_PORTS:
            return "Puerto Inusual"
        
        if 'pipeline' in entry and 'failure' in entry['pipeline']:
            return "Fallo de Pipeline"
        
        file_path = entry.get('file', {}).get('path', '')
        if file_path and any(file_path.startswith(critical_path) for critical_path in CRITICAL_FILE_PATHS):
            return "Archivo Sensible Modificado"
        
        return "Alerta General"
    except Exception as e:
        logger.error(f"Error determinando tipo de alerta: {e}")
        return "Alerta No Clasificada"

@bot.command(name='check_alerts')
async def check_alerts(ctx, log_type='logstash', lines: int = 50):
    """Revisar logs en busca de alertas importantes"""
    if lines > 200:
        await ctx.send("⚠️ Por razones de seguridad, no se pueden revisar más de 200 líneas a la vez.")
        lines = 200
    
    log_path = LOG_PATHS.get(log_type)
    if not log_path:
        await ctx.send(f"❌ Tipo de log no reconocido: {log_type}. Usa !help_logs para ver los tipos disponibles.")
        return
    
    if not os.path.exists(log_path):
        await ctx.send(f"❌ El archivo de log {log_path} no existe.")
        return
    
    await ctx.send(f"🔍 **Buscando alertas importantes en {log_type}** (últimas {lines} líneas)...")
    
    try:
        # Leer las últimas líneas del archivo
        result = read_last_lines(log_path, lines)
        lines_list = result.strip().split('\n')
        
        important_logs = []
        for line in lines_list:
            try:
                # Intentar parsear como JSON
                entry = json.loads(line.strip())
                
                # Verificar si el log es importante
                if is_important_log(entry):
                    # Determinar tipo de alerta
                    alert_type = determine_alert_type(entry)
                    formatted_json = json.dumps(entry, indent=2, ensure_ascii=False)
                    important_logs.append((alert_type, formatted_json))
            except json.JSONDecodeError:
                # No es un JSON válido, ignorar
                pass
            except Exception as e:
                logger.error(f"Error procesando línea de log: {e}")
        
        if not important_logs:
            await ctx.send("✅ No se encontraron alertas importantes en las líneas revisadas.")
            return
        
        await ctx.send(f"⚠️ **Se encontraron {len(important_logs)} alertas importantes:**")
        
        for i, (alert_type, log_json) in enumerate(important_logs, 1):
            # Dividir en chunks si es necesario
            if len(log_json) > 1990:
                chunks = [log_json[i:i+1990] for i in range(0, len(log_json), 1990)]
                await ctx.send(f"**Alerta {i}/{len(important_logs)} - Tipo: {alert_type}**")
                for chunk in chunks:
                    await ctx.send(f"```json\n{chunk}\n```")
            else:
                await ctx.send(f"**Alerta {i}/{len(important_logs)} - Tipo: {alert_type}**\n```json\n{log_json}\n```")
    
    except Exception as e:
        await ctx.send(f"❌ Error revisando logs: {e}")
        logger.error(f"Error en check_alerts: {e}")

if __name__ == "__main__":
    main()
