const http = require('node:http')

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

const host = arg('host', '127.0.0.1')
const port = Number(arg('port', '9000'))
const serverName = arg('name', 'remote')

function writeJson(response, payload) {
  const body = Buffer.from(JSON.stringify(payload))
  response.writeHead(200, {
    'content-type': 'application/json',
    'content-length': String(body.length)
  })
  response.end(body)
}

const server = http.createServer((request, response) => {
  if (request.method !== 'POST' || request.url !== '/mcp') {
    response.writeHead(404)
    response.end()
    return
  }

  const chunks = []
  request.on('data', chunk => chunks.push(chunk))
  request.on('end', () => {
    let message = {}
    try {
      const body = Buffer.concat(chunks).toString('utf8')
      message = body ? JSON.parse(body) : {}
    } catch {
      writeJson(response, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } })
      return
    }

    if (message.method === 'tools/list') {
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'safe_read_file',
              description: `Read a demo file from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: { path: { type: 'string' } },
                required: ['path'],
                additionalProperties: false
              }
            },
            {
              name: 'list_project_files',
              description: `List demo files from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: {},
                additionalProperties: false
              }
            }
          ]
        }
      })
      return
    }

    if (message.method === 'tools/call') {
      const params = message.params && typeof message.params === 'object' ? message.params : {}
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          content: [
            {
              type: 'text',
              text: `${serverName} handled ${params.name || ''}`
            }
          ]
        }
      })
      return
    }

    writeJson(response, { jsonrpc: '2.0', id: message.id, result: {} })
  })
})

server.listen(port, host)
