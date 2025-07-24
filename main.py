#!/usr/bin/env python3
"""
MCP Server com CrewAI - Agentes como Tools MCP
"""

import asyncio
import json
import logging
import os
import jwt
import uuid
import time
from datetime import datetime, timedelta
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
import uvicorn
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from crewai.llm import LLM

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "mcp-jwt-secret-key-super-secure-2024")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30


def generate_jwt_token(client_id: str, scope: str = "mcp", token_type: str = "access") -> str:
    """Gera um JWT token"""
    now = datetime.utcnow()

    if token_type == "access":
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    else:  # refresh token
        expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": client_id,  # Subject (client_id)
        "iat": int(now.timestamp()),  # Issued at
        "exp": int(expire.timestamp()),  # Expiration
        "aud": "mcp-server",  # Audience
        "iss": os.getenv("BASE_URL", "http://localhost:8003"),  # Issuer
        "scope": scope,
        "token_type": token_type,
        "jti": str(uuid.uuid4())  # JWT ID
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def generate_refresh_token(client_id: str, scope: str = "mcp") -> str:
    """Gera um refresh token JWT"""
    return generate_jwt_token(client_id, scope, "refresh")


def verify_jwt_token(token: str) -> dict:
    """Verifica e decodifica um JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")


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


@app.api_route("/debug/token", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def debug_token(request: Request):
    """Debug endpoint para verificar requisições do Claude CLI"""
    method = request.method
    headers = dict(request.headers)
    url = str(request.url)

    try:
        if method == "POST":
            content_type = headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:
                form_data = await request.form()
                body = dict(form_data)
            elif "application/json" in content_type:
                body = await request.json()
            else:
                body_bytes = await request.body()
                body = body_bytes.decode() if body_bytes else ""
        else:
            body = None
    except Exception as e:
        body = f"Error reading body: {e}"

    debug_info = {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "timestamp": datetime.now().isoformat()
    }

    logger.info(f"DEBUG REQUEST: {debug_info}")

    return JSONResponse(content={
        "message": "Debug endpoint - check logs for details",
        "request_info": debug_info
    })


# OAuth Discovery Endpoints
@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """OAuth Protected Resource Discovery"""
    base_url = os.getenv("BASE_URL", "http://localhost:8003")
    return {
        "resource_server": base_url,
        "authorization_servers": [f"{base_url}"],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/docs"
    }


@app.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource_mcp():
    """OAuth Protected Resource Discovery for MCP endpoint"""
    base_url = os.getenv("BASE_URL", "http://localhost:8003")
    return {
        "resource_server": base_url,
        "authorization_servers": [f"{base_url}"],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/docs",
        "mcp_endpoint": f"{base_url}/mcp"
    }


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """OAuth Authorization Server Discovery"""
    base_url = os.getenv("BASE_URL", "http://localhost:8003")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "scopes_supported": ["mcp"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "client_registration_types_supported": ["automatic"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "HS256"]
    }


@app.get("/.well-known/oauth-authorization-server/mcp")
async def oauth_authorization_server_mcp():
    """OAuth Authorization Server Discovery for MCP"""
    base_url = os.getenv("BASE_URL", "http://localhost:8003")
    return {
        "issuer": f"{base_url}/mcp",
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "scopes_supported": ["mcp"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "client_registration_types_supported": ["automatic"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "HS256"],
        "mcp_endpoint": f"{base_url}/mcp"
    }


# OAuth Endpoints (básicos para compatibilidade)
@app.get("/oauth/authorize")
async def oauth_authorize(
        response_type: str,
        client_id: str,
        redirect_uri: str,
        state: str = None,
        scope: str = "mcp",
        code_challenge: str = None,
        code_challenge_method: str = None
):
    """OAuth Authorization Endpoint"""
    try:
        # Validar response_type
        if response_type != "code":
            error_params = f"error=unsupported_response_type&error_description=Only+code+response_type+supported"
            if state:
                error_params += f"&state={state}"
            return RedirectResponse(url=f"{redirect_uri}?{error_params}")

        # Validar client_id (verificar se começa com mcp_client_)
        if not client_id.startswith("mcp_client_"):
            error_params = f"error=invalid_client&error_description=Invalid+client_id"
            if state:
                error_params += f"&state={state}"
            return RedirectResponse(url=f"{redirect_uri}?{error_params}")

        # Validar PKCE se fornecido
        if code_challenge and code_challenge_method != "S256":
            error_params = f"error=invalid_request&error_description=Only+S256+code_challenge_method+supported"
            if state:
                error_params += f"&state={state}"
            return RedirectResponse(url=f"{redirect_uri}?{error_params}")

        # Gerar authorization code
        import uuid
        import base64
        auth_code = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode('utf-8').rstrip('=')

        # Armazenar informações do código (em produção, usar banco de dados)
        # Por simplicidade, vamos usar um dicionário em memória
        if not hasattr(oauth_authorize, 'auth_codes'):
            oauth_authorize.auth_codes = {}

        oauth_authorize.auth_codes[auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": datetime.now().timestamp() + 600,  # 10 minutos
            "used": False
        }

        # Redirecionar com o código de autorização
        success_params = f"code={auth_code}"
        if state:
            success_params += f"&state={state}"

        logger.info(f"Authorization code gerado para client {client_id}: {auth_code}")
        return RedirectResponse(url=f"{redirect_uri}?{success_params}")

    except Exception as e:
        logger.error(f"Erro no authorize: {e}")
        error_params = f"error=server_error&error_description=Internal+server+error"
        if state:
            error_params += f"&state={state}"
        return RedirectResponse(url=f"{redirect_uri}?{error_params}")


@app.post("/oauth/token")
async def oauth_token(request: Request):
    """OAuth Token Endpoint"""
    try:
        # Obter dados do formulário
        form_data = await request.form()
        grant_type = form_data.get("grant_type")

        logger.info(f"Token request - grant_type: {grant_type}")
        logger.info(f"Form data keys: {list(form_data.keys())}")

        if grant_type == "authorization_code":
            return await handle_authorization_code_grant(form_data)
        elif grant_type == "client_credentials":
            return await handle_client_credentials_grant(form_data)
        elif grant_type == "refresh_token":
            return await handle_refresh_token_grant(form_data)
        else:
            return JSONResponse(content={
                "error": "unsupported_grant_type",
                "error_description": f"Grant type '{grant_type}' not supported"
            })

    except Exception as e:
        logger.error(f"Erro no token endpoint: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return JSONResponse(content={
            "error": "server_error",
            "error_description": f"Internal server error: {str(e)}"
        })


async def handle_authorization_code_grant(form_data):
    """Handle authorization_code grant type"""
    import hashlib
    import base64

    code = form_data.get("code")
    client_id = form_data.get("client_id")
    redirect_uri = form_data.get("redirect_uri")
    code_verifier = form_data.get("code_verifier")

    logger.info(f"Authorization code grant - code: {code}, client_id: {client_id}")
    logger.info(f"Redirect URI: {redirect_uri}, code_verifier present: {bool(code_verifier)}")

    # Verificar se o código existe e é válido
    if not hasattr(oauth_authorize, 'auth_codes'):
        logger.error("No auth_codes attribute found")
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        })

    if code not in oauth_authorize.auth_codes:
        logger.error(f"Code {code} not found in auth_codes")
        logger.info(f"Available codes: {list(oauth_authorize.auth_codes.keys())}")
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        })

    code_data = oauth_authorize.auth_codes[code]

    # Verificar se o código não foi usado
    if code_data["used"]:
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": "Authorization code already used"
        })

    # Verificar se não expirou
    if datetime.now().timestamp() > code_data["expires_at"]:
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": "Authorization code expired"
        })

    # Verificar client_id
    if client_id != code_data["client_id"]:
        return JSONResponse(content={
            "error": "invalid_client",
            "error_description": "Client ID mismatch"
        })

    # Verificar redirect_uri
    if redirect_uri != code_data["redirect_uri"]:
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": "Redirect URI mismatch"
        })

    # Verificar PKCE se foi usado
    if code_data["code_challenge"]:
        if not code_verifier:
            return JSONResponse(content={
                "error": "invalid_request",
                "error_description": "Code verifier required"
            })

        # Verificar code_challenge
        verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
        verifier_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip('=')

        if verifier_challenge != code_data["code_challenge"]:
            return JSONResponse(content={
                "error": "invalid_grant",
                "error_description": "Invalid code verifier"
            })

    # Marcar código como usado
    code_data["used"] = True

    # Gerar JWT access token e refresh token
    access_token = generate_jwt_token(client_id, code_data["scope"], "access")
    refresh_token = generate_refresh_token(client_id, code_data["scope"])

    logger.info(f"JWT tokens gerados para client {client_id}")

    response_data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # em segundos
        "refresh_token": refresh_token,
        "scope": code_data["scope"]
    }

    logger.info(f"Returning JWT token response for client {client_id}")
    return JSONResponse(content=response_data)


async def handle_client_credentials_grant(form_data):
    """Handle client_credentials grant type"""
    client_id = form_data.get("client_id")
    client_secret = form_data.get("client_secret")
    scope = form_data.get("scope", "mcp")

    # Verificar client_id
    if not client_id or not client_id.startswith("mcp_client_"):
        return JSONResponse(content={
            "error": "invalid_client",
            "error_description": "Invalid client_id"
        })

    # Verificar client_secret
    expected_secret = os.getenv("MCP_API_KEY", "mcp-secret-key-123")
    if client_secret != expected_secret:
        return JSONResponse(content={
            "error": "invalid_client",
            "error_description": "Invalid client_secret"
        })

    logger.info(f"Client credentials JWT token gerado para {client_id}")

    # Gerar JWT access token e refresh token
    access_token = generate_jwt_token(client_id, scope, "access")
    refresh_token = generate_refresh_token(client_id, scope)

    response_data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # em segundos
        "refresh_token": refresh_token,
        "scope": scope
    }

    logger.info(f"Returning client credentials JWT response for {client_id}")
    return JSONResponse(content=response_data)


async def handle_refresh_token_grant(form_data):
    """Handle refresh_token grant type"""
    refresh_token = form_data.get("refresh_token")
    client_id = form_data.get("client_id")
    scope = form_data.get("scope", "mcp")

    if not refresh_token:
        return JSONResponse(content={
            "error": "invalid_request",
            "error_description": "Refresh token is required"
        })

    try:
        # Verificar e decodificar o refresh token
        payload = verify_jwt_token(refresh_token)

        # Verificar se é um refresh token
        if payload.get("token_type") != "refresh":
            return JSONResponse(content={
                "error": "invalid_grant",
                "error_description": "Invalid refresh token type"
            })

        # Verificar client_id se fornecido
        token_client_id = payload.get("sub")
        if client_id and client_id != token_client_id:
            return JSONResponse(content={
                "error": "invalid_client",
                "error_description": "Client ID mismatch"
            })

        # Gerar novos tokens
        new_access_token = generate_jwt_token(token_client_id, scope, "access")
        new_refresh_token = generate_refresh_token(token_client_id, scope)

        logger.info(f"Refresh token usado para gerar novos tokens para client {token_client_id}")

        response_data = {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": new_refresh_token,
            "scope": scope
        }

        return JSONResponse(content=response_data)

    except Exception as e:
        logger.error(f"Erro ao processar refresh token: {e}")
        return JSONResponse(content={
            "error": "invalid_grant",
            "error_description": f"Invalid refresh token: {str(e)}"
        })


@app.post("/oauth/register")
async def oauth_register(request: Request):
    """OAuth Dynamic Client Registration Endpoint"""
    try:
        client_data = await request.json()

        # Gerar um client_id único
        import uuid
        client_id = f"mcp_client_{uuid.uuid4().hex[:8]}"

        # Para este servidor, todos os clientes registrados usam a mesma API key
        api_key = os.getenv("MCP_API_KEY", "mcp-secret-key-123")

        # Resposta de registro bem-sucedido
        base_url = os.getenv("BASE_URL", "http://localhost:8003")

        response = {
            "client_id": client_id,
            "client_secret": api_key,  # Usar a API key como client_secret
            "client_id_issued_at": int(datetime.now().timestamp()),
            "client_secret_expires_at": 0,  # Não expira
            "registration_access_token": f"reg_{uuid.uuid4().hex}",
            "registration_client_uri": f"{base_url}/oauth/register/{client_id}",
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["client_credentials"],
            "response_types": ["code"],
            "scope": "mcp",
            "redirect_uris": client_data.get("redirect_uris", []),
            "client_name": client_data.get("client_name", "MCP Client"),
            "client_uri": client_data.get("client_uri", ""),
            "logo_uri": client_data.get("logo_uri", ""),
            "contacts": client_data.get("contacts", []),
            "tos_uri": client_data.get("tos_uri", ""),
            "policy_uri": client_data.get("policy_uri", ""),
            "software_id": client_data.get("software_id", ""),
            "software_version": client_data.get("software_version", "")
        }

        logger.info(f"Cliente OAuth registrado: {client_id}")
        return response

    except Exception as e:
        logger.error(f"Erro no registro OAuth: {e}")
        return {
            "error": "invalid_client_metadata",
            "error_description": f"Registration failed: {str(e)}"
        }


@app.get("/oauth/register/{client_id}")
async def oauth_get_client(client_id: str):
    """Get OAuth Client Registration"""
    base_url = os.getenv("BASE_URL", "http://localhost:8003")
    api_key = os.getenv("MCP_API_KEY", "mcp-secret-key-123")

    return {
        "client_id": client_id,
        "client_secret": api_key,
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["client_credentials"],
        "response_types": ["code"],
        "scope": "mcp",
        "client_name": "MCP Client",
        "registration_client_uri": f"{base_url}/oauth/register/{client_id}"
    }


@app.put("/oauth/register/{client_id}")
async def oauth_update_client(client_id: str, request: Request):
    """Update OAuth Client Registration"""
    try:
        client_data = await request.json()
        base_url = os.getenv("BASE_URL", "http://localhost:8003")
        api_key = os.getenv("MCP_API_KEY", "mcp-secret-key-123")

        response = {
            "client_id": client_id,
            "client_secret": api_key,
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["client_credentials"],
            "response_types": ["code"],
            "scope": "mcp",
            "client_name": client_data.get("client_name", "MCP Client"),
            "registration_client_uri": f"{base_url}/oauth/register/{client_id}"
        }

        logger.info(f"Cliente OAuth atualizado: {client_id}")
        return response

    except Exception as e:
        return {
            "error": "invalid_client_metadata",
            "error_description": f"Update failed: {str(e)}"
        }


@app.delete("/oauth/register/{client_id}")
async def oauth_delete_client(client_id: str):
    """Delete OAuth Client Registration"""
    logger.info(f"Cliente OAuth removido: {client_id}")
    return {"message": "Client deleted successfully"}


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
                        'serverInfo': {'name': 'hello-mcp-remote', 'version': '1.0.0'}
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
                        'required': [
                            'name']
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
