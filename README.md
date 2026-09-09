# IronBrew2 Obfuscator API (Render-ready)

API lista para desplegar en **Render** que ofusca scripts Lua/Luau usando **IronBrew2** (VM + control-flow + mutaciones).

## Endpoints

| Método | Ruta              | Descripción                                      |
|--------|-------------------|--------------------------------------------------|
| GET    | `/`               | Info del servicio                                |
| GET    | `/health`         | Health check (incluye si `luac` está disponible) |
| GET    | `/ui`             | Interfaz web simple para probar                  |
| POST   | `/obfuscate`      | JSON: `{ "source": "código lua", "options": {} }` |
| POST   | `/obfuscate/file` | Multipart: campo `file` con el .lua              |

### Options (opcionales)

```json
{
  "encryptStrings": false,
  "noControlFlow": false,
  "noMutate": false,
  "noSuperOps": false,
  "noCompress": false,
  "noMinify": false,
  "preserveLines": false
}
```

### Ejemplo cURL

```bash
curl -X POST https://TU-SERVICIO.onrender.com/obfuscate \
  -H "Content-Type: application/json" \
  -H "x-api-key: TU_API_KEY" \
  -d '{"source":"print(\"hola\")","options":{"encryptStrings":true}}'
```

## Despliegue en Render

### Opción A – Docker (recomendado)

1. Sube esta carpeta a un repo de GitHub.
2. En Render → **New → Web Service**.
3. Conecta el repo.
4. **Runtime**: Docker.
5. (Opcional) Añade variable de entorno `API_KEY` con un secreto.
6. Deploy.

O usa el archivo `render.yaml` (Blueprint).

### Opción B – Native Node (sin Docker)

Render Native no trae `luac`. Tendrás que usar un build command que lo instale (puede ser frágil):

```
buildCommand: apt-get update && apt-get install -y lua5.1 && npm install
startCommand: node server.js
```

**Mejor usar Docker.**

## Variables de entorno

| Variable   | Descripción                                      |
|------------|--------------------------------------------------|
| `PORT`     | Puerto (Render lo pone automáticamente)          |
| `API_KEY`  | Si se define, se exige header `x-api-key`        |
| `NODE_ENV` | production                                       |

## Local

```bash
# Necesitas lua5.1 instalado
sudo apt install lua5.1   # o equivalente

npm install
node server.js
# → http://localhost:10000/ui
```

## Notas

- Basado en el port JS de IronBrew2 incluido en `ib2/`.
- El ofuscador genera un VM personalizado + bytecode ofuscado.
- Tamaño máximo de input ≈ 1.2 MB.
- Rate limit: 30 peticiones / minuto por IP.
