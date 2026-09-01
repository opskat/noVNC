/* global Buffer, module, require */

const net = require('node:net');
const { WebSocketServer } = require('ws');

function listenWebSocketProxy({ listenPort, targetHost, targetPort }) {
    const server = new WebSocketServer({ host: '127.0.0.1', port: listenPort });

    server.on('connection', (websocket) => {
        const socket = net.createConnection({ host: targetHost, port: targetPort });
        const pending = [];
        let connected = false;

        socket.on('connect', () => {
            connected = true;
            for (const data of pending.splice(0)) {
                socket.write(data);
            }
        });
        socket.on('data', (data) => {
            if (websocket.readyState === websocket.OPEN) {
                websocket.send(data, { binary: true });
            }
        });
        socket.on('error', () => websocket.close(1011, 'TCP proxy failure'));
        socket.on('close', () => websocket.close());

        websocket.on('message', (data, isBinary) => {
            if (!isBinary) {
                websocket.close(1003, 'Binary WebSocket frames required');
                return;
            }
            const payload = Buffer.from(data);
            if (connected) {
                socket.write(payload);
            } else {
                pending.push(payload);
            }
        });
        websocket.on('close', () => socket.destroy());
        websocket.on('error', () => socket.destroy());
    });

    return new Promise((resolve, reject) => {
        server.once('listening', () => resolve(server));
        server.once('error', reject);
    });
}

module.exports = { listenWebSocketProxy };
