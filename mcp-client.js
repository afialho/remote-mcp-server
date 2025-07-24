#!/usr/bin/env node

const https = require('https');
const http = require('http');

const SERVER_URL = process.env.REMOTE_SERVER_URL || 'https://remote-mcp-server-production-101e.up.railway.app/mcp';

// Fazer request HTTP
function makeRequest(data) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(data);
    const isHttps = SERVER_URL.startsWith('https');
    const url = new URL(SERVER_URL);
    
    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': postData.length
      }
    };

    const req = (isHttps ? https : http).request(options, (res) => {
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        try {
          const result = JSON.parse(responseData);
          resolve(result);
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    req.write(postData);
    req.end();
  });
}

// Processar entrada STDIO
process.stdin.setEncoding('utf8');
process.stdin.resume();

let inputBuffer = '';
process.stdin.on('data', async (chunk) => {
  inputBuffer += chunk;
  
  let lines = inputBuffer.split('\n');
  inputBuffer = lines.pop();
  
  for (let line of lines) {
    if (line.trim()) {
      try {
        const request = JSON.parse(line);
        await handleRequest(request);
      } catch (e) {
        console.log(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' }
        }));
      }
    }
  }
});

async function handleRequest(request) {
  try {
    if (request.method === 'initialize') {
      // Resposta local para initialize
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'http-mcp-client', version: '1.0.0' }
        }
      }));
      return;
    }

    if (request.method && request.method.startsWith('notifications/')) {
      // Ignorar notificações
      return;
    }

    // Fazer proxy para servidor HTTP
    const result = await makeRequest({
      method: request.method,
      params: request.params || {}
    });
    
    console.log(JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: result
    }));

  } catch (error) {
    if (request.id !== undefined) {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        error: { code: -1, message: error.message }
      }));
    }
  }
}

console.error('✅ HTTP MCP Client pronto');