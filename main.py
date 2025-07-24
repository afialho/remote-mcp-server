#!/usr/bin/env python3
"""
MCP Server nativo via WebSocket
"""

import asyncio
import json
import logging
import os
from datetime import datetime
import websockets
from websockets.server import serve
from mcp.server import Server
from mcp.types import Tool, TextContent

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Criar servidor MCP
mcp_server = Server("hello-mcp-remote")

@mcp_server.list_tools()
async def list_tools():
    """Lista tools disponíveis"""
    logger.info("Listando tools")
    return [
        Tool(
            name="hello",
            description="Retorna uma saudação personalizada",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Nome para cumprimentar"
                    }
                },
                "required": ["name"]
            }
        )
    ]

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Executa uma tool"""
    logger.info(f"Executando tool: {name} com argumentos: {arguments}")
    
    if name == "hello":
        user_name = arguments.get("name", "Mundo")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = f"Olá, {user_name}! 👋\n\nEste é seu MCP server NATIVO remoto!\nTimestamp: {timestamp}\nServidor: Railway WebSocket MCP"
        
        return [TextContent(type="text", text=message)]
    
    raise ValueError(f"Tool desconhecida: {name}")

class MCPWebSocketHandler:
    def __init__(self):
        self.request_id = 0
    
    async def handle_client(self, websocket, path):
        """Handler para conexões WebSocket MCP"""
        logger.info(f"Nova conexão MCP: {websocket.remote_address}")
        
        try:
            async for message in websocket:
                try:
                    # Parse da mensagem JSON-RPC
                    data = json.loads(message)
                    logger.info(f"Mensagem recebida: {data}")
                    
                    # Processar mensagem
                    response = await self.process_mcp_message(data)
                    
                    # Enviar resposta
                    await websocket.send(json.dumps(response))
                    logger.info(f"Resposta enviada: {response}")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Erro JSON: {e}")
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"}
                    }
                    await websocket.send(json.dumps(error_response))
                
                except Exception as e:
                    logger.error(f"Erro processando mensagem: {e}")
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": data.get("id") if 'data' in locals() else None,
                        "error": {"code": -1, "message": str(e)}
                    }
                    await websocket.send(json.dumps(error_response))
        
        except websockets.exceptions.ConnectionClosed:
            logger.info("Conexão MCP fechada")
        except Exception as e:
            logger.error(f"Erro na conexão: {e}")
    
    async def process_mcp_message(self, data):
        """Processar mensagem MCP e retornar resposta"""
        method = data.get("method")
        params = data.get("params", {})
        msg_id = data.get("id")
        
        if method == "initialize":
            return {
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
        
        elif method == "tools/list":
            tools = await list_tools()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.inputSchema
                        } for tool in tools
                    ]
                }
            }
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            try:
                result = await call_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": content.type,
                                "text": content.text
                            } for content in result
                        ]
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -1, "message": str(e)}
                }
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }

async def main():
    """Função principal"""
    port = int(os.environ.get("PORT", 8000))
    
    logger.info(f"🚀 Iniciando MCP Server WebSocket na porta {port}")
    
    handler = MCPWebSocketHandler()
    
    # Iniciar servidor WebSocket
    server = await serve(
        handler.handle_client,
        "0.0.0.0",
        port,
        logger=logger
    )
    
    logger.info(f"✅ MCP Server rodando em ws://0.0.0.0:{port}")
    logger.info("Aguardando conexões MCP...")
    
    # Manter servidor rodando
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())