import { createHash } from "crypto";
import EventEmitter from "events";
import { Server } from "net";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export default class AbstractSocketServer extends EventEmitter {
	clients = new Set;

	/**
	 * 
	 * @param {Object} options 
	 * @param {Number} options.port 
	 * @param {String} [options.host] 
	 * @param {Server} options.server 
	 * @param {Function} [callback] 
	 */
	constructor(options, callback) {
		super();
		Object.defineProperty(this, '_server', {value: new Server(socket => {
			socket.once('close', () => this.clients.delete(socket));
			this.clients.add(socket);
			!socket.isWebsocket && socket.on('data', data => {
				const message = data.toString("utf8").replace(/\r\n$/, '')
					, headers = Object.fromEntries(message.trim().split('\r\n').map(t => t.split(/:\s+/g).map((item, index) => index > 0 ? item : item.toLowerCase())));
				if (message.startsWith("GET") && headers["sec-websocket-key"] !== void 0) {
					this.emit('upgrade', {
						headers,
						method: 'GET'
					}, socket);
				}

				if (/^CONNECT|GET|POST|PUT/.test(message)) return;
				this.emit('message', message, response => socket.send(response));
				this.emit('data', data, response => socket.send(response))
			})
		})});
		Object.defineProperties(this, {
			options: { value: options || {} }
		});
		this._server.on('upgrade', (req, socket) => {
			if (req.method !== 'GET') return socket.emit('error', new Error("Invalid request method"));
			if (req.headers.upgrade.toLowerCase() !== 'websocket') return socket.emit('error', new Error("Invalid Upgrade header"));
			if (!socket.readable || !socket.writable) return socket.destroy();

			const key = req.headers['sec-websocket-key']
				, protocol = req.headers['sec-websocket-protocol']
				, headers = [
				"HTTP/1.1 101 Switching Protocols",
				"Upgrade: websocket",
				"Connection: Upgrade",
				`Sec-WebSocket-Accept: ${
					createHash('sha1')
						.update(key + GUID)
						.digest('base64')
				}`
			]

			protocol != void 0 && headers.push(`Sec-WebSocket-Protocol: ${protocol}`);
			socket.isWebsocket = true;
			socket.write(headers.concat('\r\n').join('\r\n'));
			this._server.emit('connection', socket)
			// socket.on('data', data => {
			// 	data = this.constructor.decodeMessage(data);
			// 	const message = data.replace(/\r\n$/, '');
			// 	this.emit('message', message, response => socket.send(response));
			// 	this.emit('data', Buffer.from(message), response => socket.send(response))
			// })
		});

		callback = callback || Array.from(arguments).at(-1);
		if (typeof callback == 'function') this.on('listening', callback);
		if (options !== void 0 && typeof options != "function") {
			if (typeof options != "object") throw new TypeError("Options must be of type: Object");
			if (options.server !== void 0) {
				if (typeof options.server != "object") throw new TypeError("Server must be of type: Object");
				options.server.on('connect', (req, socket, head) => {
					// Bridge sockets to a different port
					socket.write(
						'HTTP/1.1 200 Connection Established\r\n' +
						'Proxy-agent: Node.js-Proxy\r\n' +
						'\r\n'
					);

					this.emit("connection", socket);

					// const { port, hostname } = new URL(`http://${req.url}`);
					// const serverSocket = net.connect(port || 80, hostname, () => {
					//     socket.write(
					//         'HTTP/1.1 200 Connection Established\r\n' +
					//         'Proxy-agent: Node.js-Proxy\r\n' +
					//         '\r\n'
					//     );
					//     serverSocket.write(head);
					//     serverSocket.pipe(socket);
					//     socket.pipe(serverSocket);
					// });

					// serverSocket.on("data", function() {
					//     console.log("HELLO?")
					// })
				});

				if (options.port !== void 0) {
					this.listen(options.port || 80, options.host || null);
				} else {
					options.server.on("close", (...args) => this.emit("close", ...args));
					options.server.on("clientError", (err, socket) => socket.emit("error", err));
					options.server.on("connection", (...args) => this.emit("connection", ...args));
					options.server.on("error", (...args) => this.emit("error", ...args));
					options.server.on("listening", (...args) => this.emit("listening", ...args));
					options.server.on("upgrade", (...args) => this.emit("upgrade", ...args));
				}
			} else {
				this.listen(options.port || 80, options.host || null);
			}
		}
	}

	/**
	 * Sends a message to all clients
	 * @param {(Buffer|string)} data 
	 * @param {Function} [callback] 
	 */
	send(data, callback) {
		this.clients.forEach(socket => {
			if (socket.isWebsocket) socket.once('error', err => err.code !== 'ECONNRESET' && console.error(err));
			socket.send(data, callback)
		})
	}

	static encode(data, encoding) {
		let header;
		let payload = Buffer.from(data, encoding);
		let len = payload.length;
		if (len <= 125) {
			header = Buffer.alloc(2);
			header[1] = len;
		} else if (len <= 0xffff) {
			header = Buffer.alloc(4);
			header[1] = 126;
			header[2] = (len >> 8) & 0xff;
			header[3] = len & 0xff;
		} else { /* 0xffff < len <= 2^63 */
			header = Buffer.alloc(10);
			header[1] = 127;
			header[2] = (len >> 56) & 0xff;
			header[3] = (len >> 48) & 0xff;
			header[4] = (len >> 40) & 0xff;
			header[5] = (len >> 32) & 0xff;
			header[6] = (len >> 24) & 0xff;
			header[7] = (len >> 16) & 0xff;
			header[8] = (len >> 8) & 0xff;
			header[9] = len & 0xff;
		}
		header[0] = 0x81;
		return Buffer.concat([header, payload], header.length + payload.length)
	}

	static decode(buffer) {
		if ((buffer.readUInt8(0) & 0xF) === 0x1) {
			const length = (buffer.readUInt8(1) & 0x7F) + 4;
			const mask_key = buffer.readUInt32BE(2);
			const data = Buffer.alloc(length);
			for (let i = 0, j = 0, currentOffset = 2; i < length; ++i, j = i % 4) {
				const shift = j === 3 ? 0 : (3 - j) << 3;
				const mask = (shift === 0 ? mask_key : (mask_key >>> shift)) & 0xFF;
				const source = buffer.readUInt8(currentOffset++);
				data.writeUInt8(mask ^ source, i);
			}

			return data.toString('utf8').slice(4); // Experimental splicing
		}

		return buffer.toString('utf8')
	}

	static enhanceSocket(sock) {
		return Object.defineProperties(sock, {
			send: {value: function send() {
				if (this.isWebsocket) return this.write(SocketServer.encodeMessage(data), callback);
				return this.write(data, callback)
			}}
		})
	}
}