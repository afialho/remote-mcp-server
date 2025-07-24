# MCP Server com CrewAI

Servidor MCP integrado com agentes CrewAI para pesquisa, escrita e análise.

## Funcionalidades

- **Tool `hello`**: Saudação personalizada com timestamp
- **Tool `research`**: Agente pesquisador para análise de tópicos
- **Tool `write`**: Agente escritor para criação de conteúdo
- **Tool `analyze`**: Agente analista para insights estratégicos

## Configuração

### 1. Variáveis de Ambiente
Crie um arquivo `.env` com:
```env
OPENAI_API_KEY=sua_chave_openai_aqui
OPENAI_MODEL=gpt-4o-mini
```

### 2. Instalação Local
```bash
pip install -r requirements.txt
python main.py
```

### 3. Deploy
Deploy automático no Railway/Render conectando este repositório.

## Endpoints

- `GET /` - Status do servidor
- `GET /health` - Health check
- `POST /mcp` - Handler MCP principal

## Tools Disponíveis

### hello
Retorna saudação personalizada.

**Parâmetros:**
- `name` (string, obrigatório): Nome para cumprimentar

### research
Pesquisa e analisa informações sobre qualquer tópico usando agente especializado.

**Parâmetros:**
- `topic` (string, obrigatório): Tópico para pesquisar
- `focus` (string, opcional): Foco específico da pesquisa

### write
Cria conteúdo bem estruturado usando agente escritor especializado.

**Parâmetros:**
- `topic` (string, obrigatório): Tópico ou informações para escrever
- `style` (string, opcional): Estilo de escrita (artigo, relatório, blog, etc.)
- `length` (string, opcional): Tamanho desejado (curto, médio, longo)

### analyze
Analisa dados e fornece insights estratégicos usando agente analista.

**Parâmetros:**
- `data` (string, obrigatório): Dados ou informações para analisar
- `analysis_type` (string, opcional): Tipo de análise (tendências, padrões, recomendações, etc.)

## Exemplos de Uso

### Pesquisa
```json
{
  "method": "tools/call",
  "params": {
    "name": "research",
    "arguments": {
      "topic": "Inteligência Artificial",
      "focus": "tendências 2024"
    }
  }
}
```

### Escrita
```json
{
  "method": "tools/call",
  "params": {
    "name": "write",
    "arguments": {
      "topic": "Benefícios da automação",
      "style": "artigo",
      "length": "médio"
    }
  }
}
```

### Análise
```json
{
  "method": "tools/call",
  "params": {
    "name": "analyze",
    "arguments": {
      "data": "Vendas Q1: 100k, Q2: 150k, Q3: 120k, Q4: 180k",
      "analysis_type": "tendências"
    }
  }
}
```