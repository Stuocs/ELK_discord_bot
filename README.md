Aquí tienes un ejemplo profesional y completo de un archivo `README.md` adaptado a tu proyecto, basado en el repositorio que mencionaste y los requisitos que proporcionaste:

---

````markdown
# ELK Discord Bot

Este bot está diseñado para integrarse con un stack ELK (Elasticsearch, Logstash, Kibana) y enviar eventos relevantes a un canal de Discord. Es útil para la monitorización en tiempo real de logs del sistema y servicios como PostgreSQL, Nginx, Apache, etc.

## Requisitos Previos

- Python 3.8+
- Logstash instalado y correctamente configurado
- Stack ELK funcional (Elasticsearch y Kibana)
- Bot de Discord configurado (token)
- Acceso de escritura a los archivos de log

---

## Configuración de Logstash

Para que el bot pueda leer los logs procesados por Logstash, necesitas añadir una salida personalizada en tu configuración de Logstash. Esto se hace editando (o creando) el archivo de configuración correspondiente, por ejemplo:

**Ruta sugerida:**  
`/etc/logstash/conf.d/30-elasticsearch-output.conf`

### Añadir la siguiente salida:

```ruby
output {
  stdout {
    codec => rubydebug {
      metadata => true # Esto permite que los logs aparezcan en consola
    }
  }
  file {
    path => "/var/log/logst.log"
    codec => json_lines
    create_if_deleted => true
  }
}
````

Esto generará un archivo de logs en formato JSON que será leído por el bot para enviar eventos a Discord.

---

## Instalación

Clona el repositorio en tu máquina:

```bash
git clone https://github.com/Stuocs/ELK_discord_bot.git
cd ELK_discord_bot
```

Crea un entorno virtual e instala las dependencias:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Configuración del Bot

Edita el archivo `.env` para añadir tu token de Discord y configurar el ID del canal donde quieres enviar los logs:

```ini
DISCORD_TOKEN=tu_token_aquí
DISCORD_CHANNEL_ID=123456789012345678
```

Asegúrate también de que el archivo `bot.py` tenga las rutas adecuadas para los logs del sistema. En especial, la línea correspondiente al log de Logstash:

```python
'logstash': '/var/log/logst.log'
```

---

## Ejecución

Lanza el bot con:

```bash
python bot.py
```

Si todo está configurado correctamente, el bot se conectará a Discord y comenzará a monitorizar los logs definidos en su configuración, enviando alertas relevantes al canal especificado.

---

## Cómo Funciona

* El bot utiliza `glob` para resolver rutas con comodines como `postgresql-*.log`.
* Lee periódicamente los archivos de log definidos.
* Si detecta nuevos eventos relevantes, los formatea y los envía al canal de Discord.
* Los mensajes se formatean con información útil como timestamp, tipo de evento y contenido del log.

---

## Logs Soportados

El bot está diseñado para soportar los siguientes servicios (configurables en el código):

* `syslog`
* `auth.log`
* `kern.log`
* `iptables`
* `logstash`
* `nginx`
* `apache2`
* `mysql`
* `postgresql`

>[!WARNING ] Es posible que de fallos referentes a algunas rutas dependiendo tanto de la versión como la del sistema opertivo así como si hay diferencias en la configuración sugerida en el documento 

Puedes añadir o modificar las rutas de log directamente en el diccionario `raw_paths` dentro de `bot.py`.

---

## Notas

* Asegúrate de que el usuario que ejecuta el bot tenga permisos de lectura sobre los archivos de log.
* Puedes ajustar los filtros en Logstash para enviar solo los eventos que te interesen al archivo `/var/log/logst.log`.

---

## Licencia

Este proyecto está licenciado bajo los términos del repositorio original.

```

---

¿Deseas que este contenido se inserte automáticamente en un archivo `README.md` en el proyecto? Puedo ayudarte a hacerlo.
```
