# Lua Obfuscator (Render)

Archivos planos, sin carpetas internas:

| Archivo        | Qué es                          |
|----------------|---------------------------------|
| `server.js`    | API Express                     |
| `obfuscate.js` | Lógica de ofuscación (puro JS)  |
| `index.html`   | UI web                          |
| `package.json` | Dependencias                    |
| `README.md`    | Este archivo                    |

## Local

```bash
npm install
node server.js
# → http://localhost:10000
```

## Render

1. Sube estos archivos a un repo.
2. New Web Service → **Node**.
3. Build: `npm install`
4. Start: `node server.js`
5. (Opcional) env `API_KEY=tu_secreto`

No necesita Docker ni `luac`.

## API

```bash
curl -X POST https://TU.onrender.com/obfuscate \
  -H "Content-Type: application/json" \
  -d '{"source":"print(\"hola\")","options":{"encryptStrings":true}}'
```

Opciones: `encryptStrings`, `mangleNames`, `encodeNumbers`, `junkCode`, `controlFlow`, `minify`.
