import EventEmitter from "events";
import { createReadStream, existsSync } from "fs";
import { readdir, stat } from "fs/promises";
import { basename, dirname, extname } from "path";

const parseStatus = (status, data) => {
	const defaultStatus = 501;
	status ??= defaultStatus;
	if (typeof status == 'object') {
		data = status;
		status = data.code ?? data.status ?? data.statusCode ?? defaultStatus;
	}

	return { data, status }
};

// Convert to Transform -- when piping through res, pipe through Pipeline
// Optional, devs can pipe raw content through stream to avoid Pipeline
export default class ServerResponse extends EventEmitter {
	#timeout = null;

	status = null;
	constructor(server, req, pipeline) {
		super();
		Object.defineProperties(this, {
			deferred: { value: false, writable: true },
			headers: { enumerable: true, value: new Headers },
			headersSent: { value: false, writable: true },
			req: { value: req },
			server: { value: server },
			stream: { value: req.stream }
		});
		req.stream.once('close', () => {
			clearTimeout(this.#timeout);
			this.#timeout = null;
			this.emit('end')
		});
		this.#timeout = setTimeout(() => !this.finished && !this.headersSent && this.writeHead(408).end(), 10e3)
	}

	continue() {
		switch (this.req.method) {
		case 'GET': {
			const domainFolder = this.req.headers.subdomain ? this.req.headers.subdomain + '.' + (this.server.options.hostname || this.req.authority) : 'public';
			this.sendFile(`${domainFolder}${this.req.path.replace(/\/$/, '')}${/\.\w*$/.test(this.req.path) ? '' : '/index.html'}`);
		} break;
		case 'HEAD':
		case 'OPTIONS': this.writeHead(200).end(); break;
		default: this.writeHead(404).end()
		}
	}

	cookie(key, value, options = {}) {
		const attrs = Object.entries(options).map(([k, v]) =>
			k.replace(/^\w/, c => c.toUpperCase()) + (v === true ? '' : `=${v}`)
		).join('; ');
		this.headers.append('Set-Cookie', `${key}=${value}${attrs ? '; ' + attrs : ''}`);
		return this
	}

	/**
	 * Set CORS headers
	 * @param {Object} options 
	 */
	cors(options) {
		options.allowCredentials && this.req.origin && this.headers.set('Access-Control-Allow-Credentials', true);
		options.allowHeaders && this.headers.set('Access-Control-Allow-Headers', options.allowHeaders);
		options.allowMethods && this.headers.set('Access-Control-Allow-Methods', options.allowMethods || 'GET');
		this.headers.set('Access-Control-Allow-Origin', this.req.origin || '*');
		this.headers.set('Access-Control-Max-Age', options.maxAge ?? 2592e3)
	}

	defer() {
		if (!this.deferred) {
			clearTimeout(this.#timeout);
			this.#timeout = null;
			Object.defineProperty(this, 'deferred', { value: true, writable: false });
		}
		return true
	}

	async downloadFile(path) {
		if (existsSync(path)) {
			this.headers.set('content-disposition', `attachment; filename="${encodeURIComponent(basename(path))}"`);
			const { size } = await stat(path);
			this.headers.set('content-length', size);
		}

		this.sendFile(path)
	}

	end(data) {
		this.stream.end(this.req.method !== 'HEAD' && data || null)
	}

	redirect(url, status = 307) {
		this.writeHead(status, { 'location': url });
		this.stream.end()
	}

	reject() {
		const { data, status } = parseStatus(...arguments);
		if (status < 400) throw new RangeError("Invalid status code: " + status + ". Rejection code must be greater than or equal to 400");
		this.sendStatus(status, data)
	}

	resolve() {
		const { data, status } = parseStatus(...arguments);
		if (status >= 400) throw new RangeError("Invalid status code: " + status + ". Resolution code must be smaller than 400");
		this.sendStatus(status, data)
	}

	send(data) {
		this.resolve(200, data)
	}

	async sendFile(path, pipeline = this.server.pipeline) {
		// if (domainify.test(path)) path = domainify.call(this.req, path);
		let contentType = /* this.server.allowedMimeTypes.parse(path); // */ this.server.allowedMimeTypes[extname(path).toLowerCase()];
		if (!contentType) return this.reject(415, `Sorry, file extension ${extname(path)} is not currently supported.`);
		if (contentType.startsWith('image') && !existsSync(path)) {
			path = path.replace(extname(path), '');
			const dir = dirname(path);
			if (existsSync(dir)) {
				const files = await readdir(dir).then(files =>
					files.filter(basename =>
						this.server.allowedMimeTypes[extname(basename)]?.startsWith('image/')
					)
				);
				path = dir + '/' + files.find(file => basename(file, extname(file)) === basename(path));
				this.req.actualPath = path;
			}
		}

		// let referer = URL.canParse(this.req.headers.referer) && new URL(this.req.headers.referer);
		// let relativePath = (this.req.headers.subdomain ? this.req.authority : 'public') + (referer && (await stat((this.req.headers.subdomain ? this.req.authority : 'public') + referer.pathname).isDirectory() ? referer.pathname.replace(/\/?$/, '/') : dirname(referer.pathname))) + this.req.path.replace(/^\//, '');
		// referer &&  && (routeUrl += dirname(referer.pathname))

		// get absolute/relative path
		// let cwd = process.cwd().replace(/\\/g, '/') + '/';
		// path = path.replace(new RegExp('^(' + cwd + ')?'), cwd);

		if (!existsSync(path)) {
			contentType = 'text/plain';
			path = 'public/404.html';
			if (!existsSync(path)) return this.reject(404, 'Error: File Not Found');
		}

		// this.statusCode = 200;
		// this.setHeader('Content-Type', contentType);
		this.writeHead(200, {
			// 'content-disposition': `inline; filename="${encodeURIComponent(basename(path))}"`,
			'content-type': contentType
		});

		let fileStream = createReadStream(path);
		if (pipeline) {
			const transformStream = pipeline._stream(this.req, this, contentType);
			fileStream = fileStream.pipe(transformStream);
		}

		fileStream.pipe(this.stream);
		fileStream.on('error', err => {
			console.error(err);
			if (!this.headersSent) {
				this.statusCode = 500;
				this.end('Error reading the file');
			} else {
				this.stream.destroy(err)
			}
		});

		this.on('close', () => fileStream.destroy())
	}

	sendStatus(status, data) {
		let contentType = 'text/plain';
		if (typeof data == 'object' && data !== null) {
			contentType = 'application/json';
			data = JSON.stringify(data);
		}

		const headers = { ':status': status, 'content-type': contentType };
		// data && (headers['content-length'] = Buffer.byteLength(data));
		this.writeHead(headers).end(data)
	}

	writeHead(status = 200, headers = {}) {
		if (this.headersSent) throw new Error('Headers have already been sent');
		if (typeof status == 'object') headers = status;
		else if (typeof status == 'number') headers = { ':status': status, ...headers };
		for (const [key, value] of this.headers.entries()) headers[key] = value;

		const cookies = this.headers.getSetCookie();
		if (cookies?.length) headers['set-cookie'] = cookies;

		this.stream.respond(headers);
		for (const key in headers) key.startsWith(':') || this.headers.set(key, headers[key]);
		Object.freeze(this.headers);
		Object.defineProperty(this, 'status', { value: headers[':status'], writable: false });
		Object.defineProperty(this, 'headersSent', { value: true, writable: false });
		return this
	}
}