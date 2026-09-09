# QyrexOBF Discord Bot (MAX)

## 1. Crea el bot
1. https://discord.com/developers/applications → New Application
2. Bot → Add Bot → Reset Token → copia `DISCORD_TOKEN`
3. Bot → Privileged Gateway Intents → activa **Message Content Intent**
4. OAuth2 → URL Generator → scopes: `bot` `applications.commands`
   permissions: Send Messages, Attach Files, Read Message History
5. Abre la URL e invita el bot a tu servidor
6. Copia también el **Application ID** → `CLIENT_ID`

## 2. Variables de entorno (Render / VPS)
```
DISCORD_TOKEN=tu_token
CLIENT_ID=tu_application_id
ANTI_TAMPER=true
```

## 3. Arranque
```bash
npm install
# calentar engines + bot
node bot.js
```

En Render Docker, cambia el CMD a:
```
node bot.js
```

## 4. Uso en Discord
- `/obf` + archivo `.lua`
- o `!obf` + archivo adjunto
- o `!obf` + bloque ```lua ... ```

El bot responde con `qyrexobf-max.lua` cuando termina (1–3 min).
No depende del timeout HTTP de la web.
