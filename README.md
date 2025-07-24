# MCP Hello World Server

Servidor MCP simples para validação de funcionamento remoto.

## Funcionalidades

- Tool `hello`: Retorna saudação personalizada com timestamp

## Como usar

### Local
```bash
pip install -r requirements.txt
python main.py
```

### Deploy
Deploy automático no Railway/Render conectando este repositório.

## Endpoints

- `GET /` - Status do servidor
- `GET /health` - Health check  
- `POST /mcp` - Handler MCP principal

## Tool disponível

### hello
Retorna saudação personalizada.

**Parâmetros:**
- `name` (string, obrigatório): Nome para cumprimentar

**Exemplo:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "hello",
    "arguments": {
      "name": "João"
    }
  }
}
```