#!/usr/bin/env python3
"""
MCP Server via HTTP - Simples e funcional
"""

import json
import logging
import os
from datetime import datetime
from fastapi import FastAPI, Request
import uvicorn

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Hello World MCP Server")

@app.get("/")
async def root():
    return {"message": "Hello World MCP Server está rodando!", "timestamp": datetime.now().isoformat()}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/mcp")
async def mcp_handler(request: Request):
    """Handler principal para requisições MCP"""
    try:
        data = await request.json()
        method = data.get("method")
        params = data.get("params", {})
        msg_id = data.get("id")  # Importante para JSON-RPC
        
        logger.info(f"Recebida requisição MCP: {method} (id: {msg_id})")
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "hello-mcp-remote",
                        "version": "1.0.0"
                    }
                }
            }
            logger.info(f"Enviando resposta initialize: {response}")
            return response
        
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "hello",
                            "description": "Retorna uma saudação personalizada",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Nome para cumprimentar"
                                    }
                                },
                                "required": ["name"]
                            }
                        }
                    ]
                }
            }
            logger.info(f"Enviando resposta tools/list: {response}")
            return response
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            logger.info(f"Chamando tool: {tool_name} com argumentos: {arguments}")
            
            if tool_name == "hello":
                user_name = arguments.get("name", "Mundo")
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                message = f"Olá, {user_name}! 👋\n\nEste é seu MCP server REMOTO funcionando!\nTimestamp: {timestamp}\nServidor: Railway HTTP direto"
                
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": message
                            }
                        ]
                    }
                }
                logger.info(f"Enviando resposta hello: {response}")
                return response
            else:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -1,
                        "message": f"Tool desconhecida: {tool_name}"
                    }
                }
                logger.error(f"Tool desconhecida: {tool_name}")
                return error_response
        
        else:
            error_response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Método desconhecido: {method}"
                }
            }
            logger.error(f"Método desconhecido: {method}")
            return error_response
            
    except Exception as e:
        logger.error(f"Erro no handler MCP: {e}")
        return {
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "error": {
                "code": -32603,
                "message": str(e)
            }
        }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)