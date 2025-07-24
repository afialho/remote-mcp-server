#!/usr/bin/env python3
"""
MCP Server com CrewAI - Agentes como Tools MCP
"""

import logging
import os
from datetime import datetime
from fastapi import FastAPI, Request
import uvicorn
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from crewai.llm import LLM

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CrewAI MCP Server")

# Configurar LLM
llm = LLM(
    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
    api_key=os.getenv("OPENAI_API_KEY")
)

# Definir agentes CrewAI
research_agent = Agent(
    role="Pesquisador",
    goal="Pesquisar e analisar informações sobre qualquer tópico solicitado",
    backstory="Você é um pesquisador experiente com habilidades excepcionais para encontrar, analisar e sintetizar informações de diversas fontes.",
    llm=llm,
    verbose=True
)

writer_agent = Agent(
    role="Escritor",
    goal="Criar conteúdo bem estruturado e envolvente baseado em informações fornecidas",
    backstory="Você é um escritor profissional especializado em transformar informações complexas em conteúdo claro, conciso e envolvente.",
    llm=llm,
    verbose=True
)

analyst_agent = Agent(
    role="Analista",
    goal="Analisar dados e fornecer insights estratégicos",
    backstory="Você é um analista experiente capaz de identificar padrões, tendências e fornecer recomendações baseadas em dados.",
    llm=llm,
    verbose=True
)


@app.get("/")
async def root():
    return {"message": "Hello World MCP Server está rodando!", "timestamp": datetime.now().isoformat()}


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/mcp")
async def mcp_handler(request: Request):
    """Handler principal para requisições MCP"""
    data = await request.json()
    method = data.get("method")
    params = data.get("params", {})

    logger.info(f"Requisição MCP autenticada: {method}")
    if method == 'initialize':
        response = {'jsonrpc': '2.0', 'id': 0,
                    'result': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {'tools': {}},
                        'serverInfo': {
                            'name': 'agilize-tools-mcp', 'version': '0.0.1'
                        }
                    }}
        logger.info(f"Enviando resposta: {response}")
        return response
    elif method == 'tools/list':
        response = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'tools': [
                {
                    'name': 'hello',
                    'description': 'Retorna uma saudação personalizada',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'name': {
                                'type': 'string',
                                'description': 'Nome para cumprimentar'}},
                        'required': ['name']
                    }
                },
                {
                    'name': 'research',
                    'description': 'Pesquisa informações sobre um tópico',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'topic': {
                                'type': 'string',
                                'description': 'Tópico a ser pesquisado'},
                            'focus': {
                                'type': 'string',
                                'description': 'Foco da pesquisa'}},
                        'required': [
                            'topic']
                    }
                },
                {
                    'name': 'write',
                    'description': 'Escreve um texto sobre um tópico',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'topic': {
                                'type': 'string',
                                'description': 'Tópico a ser abordado'},
                            'style': {
                                'type': 'string',
                                'description': 'Estilo de escrita (ex: artigo, relatório, poema, etc.)'},
                            'length': {
                                'type': 'string',
                                'description': 'Tamanho do texto (ex: curto, médio, longo)'}},
                        'required': [
                            'topic']
                    }
                },
                {
                    'name': 'analyze',
                    'description': 'Analiza um texto.',
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'text': {
                                'type': 'string',
                                'description': 'Texto a ser analisado'},
                            'targetLanguage': {
                                'type': 'string',
                                'description': 'Idioma de destino'}},
                        'required': ['text', 'targetLanguage']
                    }
                }
            ]}
        }
        logger.info(f"Enviando resposta: {response}")
        return response
    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        logger.info(f"Chamando tool: {tool_name} com argumentos: {arguments}")

        try:
            if tool_name == "hello":
                user_name = arguments.get("name", "Mundo")
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                message = f"Olá, {user_name}! 👋\n\nEste é seu MCP server com CrewAI funcionando!\nTimestamp: {timestamp}\nServidor: Railway/Cloud"

                response = {
                    "jsonrpc": "2.0",
                    "id": 2,
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

            elif tool_name == "research":
                topic = arguments.get("topic")
                focus = arguments.get("focus", "")

                # Criar tarefa para o agente pesquisador
                task_description = f"Pesquise sobre: {topic}"
                if focus:
                    task_description += f" com foco em: {focus}"

                task = Task(
                    description=task_description,
                    agent=research_agent,
                    expected_output="Um relatório detalhado com informações relevantes sobre o tópico pesquisado"
                )

                crew = Crew(agents=[research_agent], tasks=[task])
                result = crew.kickoff()

                response = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"🔍 **Pesquisa sobre: {topic}**\n\n{result}"
                            }
                        ]
                    }
                }
                return response

            elif tool_name == "write":
                topic = arguments.get("topic")
                style = arguments.get("style", "artigo")
                length = arguments.get("length", "médio")

                task_description = f"Escreva um {style} de tamanho {length} sobre: {topic}"

                task = Task(
                    description=task_description,
                    agent=writer_agent,
                    expected_output=f"Um {style} bem estruturado e envolvente sobre o tópico solicitado"
                )

                crew = Crew(agents=[writer_agent], tasks=[task])
                result = crew.kickoff()

                response = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"✍️ **{style.title()} sobre: {topic}**\n\n{result}"
                            }
                        ]
                    }
                }
                return response

            elif tool_name == "analyze":
                data = arguments.get("data")
                analysis_type = arguments.get("analysis_type", "análise geral")

                task_description = f"Analise os seguintes dados/informações com foco em {analysis_type}: {data}"

                task = Task(
                    description=task_description,
                    agent=analyst_agent,
                    expected_output="Uma análise detalhada com insights e recomendações baseadas nos dados fornecidos"
                )

                crew = Crew(agents=[analyst_agent], tasks=[task])
                result = crew.kickoff()
                response = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"📊 **Análise - {analysis_type}**\n\n{result}"
                            }
                        ]
                    }
                }
                return response

            else:
                error_response = {"error": f"Tool desconhecida: {tool_name}"}
                logger.error(f"Tool desconhecida: {tool_name}")
                return error_response

        except Exception as e:
            logger.error(f"Erro ao executar tool {tool_name}: {e}")
            return {"error": f"Erro ao executar {tool_name}: {str(e)}"}

    else:
        error_response = {"error": f"Método desconhecido: {method}"}
        logger.error(f"Método desconhecido: {method}")
        return error_response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8003))
    uvicorn.run(app, host="0.0.0.0", port=port)
