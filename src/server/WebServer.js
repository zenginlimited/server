import EventEmitter from "events";
import { createReadStream, existsSync, readdirSync } from "fs";
import { readdir, stat } from "fs/promises";
import { Server as Server } from "http";
import { Server as SecureServer } from "https";
import { isIP } from "net";
import { basename, dirname, extname, matchesGlob } from "path";
// import sharp from "sharp";
import mimeTypes from "../utils/mimeTypes.js";
import Pipeline from "./Pipeline.js";

const SOCIAL_BOTS = /(facebookexternalhit|Discordbot|Twitterbot|LinkedInBot|WhatsApp)/i
	, OTHER_BOTS = /(Googlebot|bingbot|DuckDuckBot|Slurp|YandexBot)/i;

export default class WebServer extends EventEmitter {
	static Pipeline = Pipeline;

	#protected = new Map();
	#rateLimits = new Map();
	#requests = {};
	#routes = new Map();

	/**
	 * 
	 * @param {object} [options]
	 * @param {number} options.port
	 * @param {string} [options.host]
	 * @param {boolean} [options.redirectProtocol]
	 * @param {function} [callback]
	 */
	constructor(options, callback) {
		const isSecure = options.isSecure || String(options.port).endsWith(443);
		if (!isSecure) {
			if (options.redirectProtocol) {
				new SecureServer(options, (req, res) => {
					// console.log('REQUEST, SECURE', req.url)
					const host = req.headers.host.replace(/:\d+$/, ''); // Remove port if any
					res.writeHead(301, { Location: `http://${host}${req.url}` }).end()
				}).listen(443, '::');
			} else if (options.allowUnsecure) {
				new SecureServer(options, (req, res) => this._server.emit('request', req, res)).listen(443, '::');
			}
		}

		super();
		Object.defineProperty(this, '_server', { value: new (isSecure ? SecureServer : Server)(options, async (req, res) => {
			req.on('error', err => {
				if (err.code === 'ECONNRESET') {
					Object.defineProperty(req, 'aborted', { value: true, writable: false });
					if (!res.writableEnded) res.destroy();
				} else {
					console.error('Request error:', err)
				}
			});
			res.on('error', err => console.error('Response error:', err));
			req.on('abort', () => console.log('Request was aborted by the client'));
			options.debug && res.on('close', () =>
				console.log(new Date(), `\x1b[3${2 - (req.aborted || res.statusCode >= 400) + (res.statusCode >= 300 && res.statusCode < 400)}m${req.aborted ? '\x1b[9m' : ''}` + req.method + '\x1b[0m', res.statusCode, (req.headers.subdomain ? `\x1b[2m${req.headers.subdomain}.\x1b[0m` : '') + req.url, `\x1b[2m${req.ip}\x1b[0m`)
			);

			await this.constructor.enhanceReq(req);
			this.constructor.enhanceRes(res);
			// this._preprocessReq();
			if (!req.isIPInternal() && this.#rateLimit(req)) {
				res.setHeader('retry-after', (60 - Math.floor((Date.now() - this.#rateLimits.get(req.ip)) / 1e3)));
				return res.reject(429, { message: "You're doing that too often! Try again in " + (60 - Math.floor((Date.now() - this.#rateLimits.get(req.ip)) / 1e3)) + " seconds." });
			}

			try { req.url = decodeURIComponent(req.url) }
			catch (error) {
				console.error(`Failed to decode "${req.url}":`, error);
				return res.reject(400, { message: "Malformed URI: " + req.url });
			}

			// const referer = URL.canParse(req.headers.referer) ? new URL(req.headers.referer) : null
			// 	, refererHost = referer ? referer.host : null;
			// options.debug && console.log(req.url, 'Converted to relative path:', resolveRelativePath(req.url, req.headers.referer));
			// options.debug && console.log(refererHost, req.headers.host)
			if (/* (!referer || refererHost !== req.headers.host) && */ options.allowCORS) {
				req.headers.origin && res.setHeader('Access-Control-Allow-Credentials', true);
				res.setHeader('Access-Control-Allow-Methods', 'DELETE, GET, PATCH, POST, PUT')
				.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Range')
				.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*')
				.setHeader('Access-Control-Max-Age', 2592e3); // 30 days
			}

			if (req.method === 'OPTIONS') return res.writeHead(204).end();

			Object.defineProperty(req.headers, 'subdomains', { value: [], writable: true });
			let subdomain = null;
			if (!isIP(req.headers.host) && req.headers.host) {
				let hostparts = req.headers.host.split(/\./g);
				if (hostparts.length > 2) {
					let subdomains = hostparts.slice(0, -2);
					subdomain = subdomains.join('.');
					req.headers.subdomains.push(...subdomains);
				}
			}

			options.forwardWWW && subdomain === 'www' && (subdomain = null);
			req.headers.subdomain = subdomain;
			req.headers.domain = req.headers.host?.replace(subdomain + '.', '');
			if (req.method !== 'GET' && req.method !== 'HEAD') {
				try {
					req.body = await new Promise((resolve, reject) => {
						const chunks = [];
						let length = 0;
						req.on('error', reject);
						req.on('data', chunk => {
							chunks.push(chunk);
							length += chunk.length;
							// if (length > process.env.MAX_REQUEST_BODY_LENGTH /* 1e6 */) {
							// 	req.destroy(); // prevent DOS
							// 	reject(new Error('Request body too large'));
							// }
						});
						req.on('end', () => {
							const body = Buffer.concat(chunks)
								, contentType = req.headers['content-type'];
							if (contentType?.startsWith('application/octet-stream')) resolve(body);
							else if (contentType?.startsWith('multipart/form-data')) {
								try {
									const boundary = /boundary=(.+)/.exec(contentType)?.[1];
									if (!boundary) throw new Error('Boundary not found');

									const parts = parseMultipartFormData(body, boundary);
									const multipartBody = Object.defineProperty({ files: [] }, 'parts', { value: parts, writable: true });
									for (const part of parts) {
										if (part.fileName && multipartBody.files.push(part.file)) {
											multipartBody[part.fieldName] = part.file; continue;
										}
										multipartBody[part.fieldName] = part.data.toString().replace(/\r\n$/, '');
									}

									resolve(multipartBody);
								} catch (err) { reject(err) }
							} else if (body.length > 0) {
								try { resolve(JSON.parse(body.toString())) }
								catch (err) { reject(err) }
							} else resolve(null)
						})
					});
				} catch(err) {
					return res.reject(400, { error: err.message });
				}
			}

			req.isBot() && console.log('[CRAWLER DETECTED]', req.headers['user-agent']);

			const isRouteProtected = this.#isProtected(req.url, { subdomain });
			if (isRouteProtected) {
				let authorization = req.headers.authorization || (isRouteProtected.cookie && req.cookies.get(isRouteProtected.cookie))
					, redirectPath = isRouteProtected.authRedirect;
				if ((!authorization || !this.#authenticate(authorization, isRouteProtected)) && (!redirectPath || req.url !== redirectPath) && (!isRouteProtected.authEndpoint || !req.url.startsWith(isRouteProtected.authEndpoint))) {
					if (redirectPath) {
						// let returnPath = '';
						// req.url !== '/' && (returnPath += '?return=' + encodeURI(req.url));
						return res.writeHead(302, { 'Location': pathify.call(req, redirectPath, { temporary: true }) /* redirectPath + returnPath */ }).end();
					}

					return res.writeHead(401, { 'WWW-Authenticate': `Basic realm="${options.host || 'App'}"` }).end();
				}
			}

			if (req.params.has('download')) {
				return res.downloadFile(`${subdomain ? (options.host ? subdomain + '.' + options.host : req.headers.host) : 'public'}${req.url.replace(/\/$/, '')}${/\.\w*$/.test(req.url) ? '' : '/index.html'}`);
			}

			const saveData = 'on' === req.headers['save-data'];
			let route = this.#route(req.method, (subdomain !== null ? `${subdomain}.` : '') + req.url);
			if (typeof route == 'function') {
				// add :id wildcard options
				if (route.isDynamic) {
					Object.defineProperty(req, 'routeMap', {
						value: new Map(),
						writable: true
					});

					try {
						let identifiers = []
						, regex = route.glob;
						if (regex.includes('.')) {
							regex = regex.replace('.', '\\.');
						}

						regex = regex.replace(/:([^\/]+)/g, (_, identifier) => {
							identifiers.push(identifier);
							return '([^/]+)'
						});
						regex = new RegExp('^' + regex + '$');
						const [_, ...values] = regex.exec((subdomain !== null ? `${subdomain}.` : '') + req.url);
						if (values && values.length > 0) {
							for (const value in values) {
								req.routeMap.set(identifiers[value], values[value]);
							}
						}
					} catch (err) {
						console.error('Failed to set identifiers:', err);
					}
				}

				// Request timeout
				// res.setTimeout(10e3, () => !res.deferred && !res.finished && res.writeHead(408).end());
				Object.defineProperty(res, '_timeout', {
					configurable: true,
					value: setTimeout(() => !res.finished && res.writeHead(408).end(), 10e3)
				});
				try {
					let result = route(req, res);
					if (result instanceof Promise) result = await result;
					if (result !== false || res.finished) return;
				} catch (err) {
					console.error('Unhandled error in request processing:', err);
					return !res.finished && res.reject(500, 'Internal Server Error');
				}
			}

			res.sendDefault(options);
		}), writable: true });
		Object.defineProperty(this, 'listen', { value: this._server.listen.bind(this._server), writable: true });
		if (typeof (callback ||= arguments[arguments.length - 1]) == 'function') this.on('listening', callback);
		if (options && typeof options != 'function') {
			if (typeof options != 'object') throw new TypeError("Options must be of type: Object");
			Object.defineProperty(this, 'options', { value: options });
			// this.listen(options.port ?? 80, options.host ?? null)
		}
	}

	#authenticate(authorization, config) {
		let match = /\S+$/.exec(authorization)?.[0];
		return config.authCallback && config.authCallback(match)
	}

	#isProtected(path, { subdomain } = {}) {
		subdomain && (path = subdomain + '.' + path);
		let wildCards = Array.from(this.#protected.keys()).filter(path => path.endsWith('*'));
		for (let protectedPath of wildCards) {
			// console.log(path.matchesGlob(path, wildCards));
			let regex = new RegExp(protectedPath.replace(/\./g, '\\.').replace('*', '.*'));
			if (regex.test(path)) {
				path = protectedPath;
				break;
			}
		}

		return this.#protected.has(path) && this.#protected.get(path)
	}

	#matchesGlob(path, glob) {
		if (glob.includes('?'))
			glob = glob.replace(/\?$/g, '.');

		if (glob.includes('*')) {
			glob = glob.replace(/(?<!\*)(\*)(?!\*)/g, '[^/]$1');
			if (glob.includes('**'))
				glob = glob.replace(/(\*){2}/g, '.$1');
		}

		if (glob.includes('[!'))
			glob = glob.replace(/(?<=\[)(\!)(?=.+\])/g, '^');

		// match :id wildcard options
		if (glob.includes('/:'))
			glob = glob.replace(/:[^\/]+/g, '[^/]+');

		const globRegex = new RegExp('^' + glob + '$');
		return globRegex.test(path)
	}

	#rateLimit(req) {
		// only ignore if content type is octet stream in req or res, not accept
		if (req.headers.accept?.startsWith('application/octet-stream') || req.headers['content-type']?.startsWith('application/octet-stream')) return; // only whitelist chunked file upload paths?
		let requestCache = this.#requests[req.ip] ||= {};
		requestCache[req.url] = 1 + (requestCache[req.url] | 0),
		requestCache.timer && clearTimeout(requestCache.timer);
		Object.defineProperty(requestCache, 'timer', {
			value: setTimeout(() => delete this.#requests[req.ip], 8e3),
			writable: true
		});
		if (requestCache[req.url] > 33) {
			this.#rateLimits.set(req.ip, Date.now());
			requestCache.rateLimitTimer && clearTimeout(requestCache.rateLimitTimer);
			Object.defineProperty(requestCache, 'rateLimitTimer', {
				value: setTimeout(() => this.#rateLimits.delete(req.ip), 6e4),
				writable: true
			});
			delete requestCache[req.url];
		}

		return this.#rateLimits.has(req.ip)
	}

	#route(method, path) {
		const route = this.#routes.get(method) || new Map();
		if (!path) return route;
		let match = route.get(path);
		if (!match) {
			// match :id wildcard options
			const globs = Array.from(route.keys()).filter(r => r.includes('*') || /:\w+/.test(r)).sort((a, b) => b.length - a.length) // Array.from(route.keys()).filter(rout => rout.includes('*')).sort((a, b) => b.length - a.length)
				, glob = globs.find(glob => this.#matchesGlob(path, glob) /* Match everything, and I mean everything */ /* matchesGlob(path, rout) */);
			if (glob) {
				const globMatch = route.get(glob)
					, matchesException = globMatch.exceptions && globMatch.exceptions.find(glob => this.#matchesGlob(path, glob));
				if (!matchesException) {
					match = route.get(glob);
				}
			}
		}

		return match || route.get("*")
	}

	#saveRoute(method, path, callback, exceptions) {
		if (typeof path != "string") {
			if (!Array.isArray(path)) throw new TypeError("Path must be of type: string");
			for (const p of path) this.#saveRoute(method, p, callback, exceptions);
			return;
		}
		if (typeof callback != "function") throw new TypeError("Callback must be of type: function");
		if (!this.#routes.has(method))
			this.#routes.set(method, new Map());

		if (typeof exceptions == 'object' && exceptions !== null) {
			Object.defineProperty(callback, 'exceptions', {
				value: Object.values(exceptions),
				writable: true
			});
		}

		Object.defineProperty(callback, 'glob', { value: path, writable: true });
		Object.defineProperty(callback, 'isDynamic', { value: /\/:.+/.test(path), writable: true });
		this.#route(method).set(path, callback)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	auth(path, callback) {
		if (typeof path != "string") throw new TypeError("Path must be of type: string");
		if (typeof callback != "function") throw new TypeError("Callback must be of type: function");
		this.#protected.set(path, Object.assign({ authCallback: callback }, this.#protected.get(path)))
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	delete(path, callback) {
		return this.#saveRoute('DELETE', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	get(path, callback) {
		return this.#saveRoute('GET', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	head(path, callback) {
		return this.#saveRoute('HEAD', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	patch(path, callback) {
		return this.#saveRoute('PATCH', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {function} callback
	 */
	post(path, callback) {
		return this.#saveRoute('POST', ...arguments)
	}

	/**
	 * Protect a file or directory
	 * @param {(string|Iterable)} path
	 * @param {object} [config]
	 * @param {function} config.authCallback
	 * @param {string} [config.authEndpoint]
	 * @param {string} [config.authRedirect]
	 * @param {string} [config.cookie]
	 * @param {string} callback
	 */
	protect(path, config, callback) {
		if (typeof path != 'string') {
			if (!Array.isArray(path)) throw new TypeError("Path must be of type: string");
			const args = Array.prototype.slice.call(arguments, 1);
			for (const p of path) this.protect(p, ...args);
			return;
		}

		if (typeof config == 'function') config = { authCallback: config };
		else if (typeof callback == 'function') Object.assign(config, { authCallback: callback });
		this.#protected.set(path, Object.assign({}, this.#protected.get(path), config))
	}

	/**
	 * 
	 * @param {string} path 
	 * @param {function} callback 
	 */
	put(path, callback) {
		return this.#saveRoute('PUT', ...arguments)
	}

	static enhanceReq(req) {
		let ip = req.headers['cf-pseudo-ipv4'] || req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || null;
		if (ip) {
			if (ip.includes(',')) ip = ip.split(',')[0].trim();
			if (ip.startsWith('::ffff:')) ip = ip.slice(7);
		}

		let search = null;
		// [req.url, params] = req.url.split('?');
		req.url = req.url.replace(/\?.*/, match => {
			search = match;
			return ''
		});

		return Object.defineProperties(req, {
			aborted: { value: false, writable: true },
			body: { value: null, writable: true },
			cookies: { value: parseCookieHeader(req.headers.cookie) },
			ip: { value: ip || null },
			isBot: {value: function isBot() {
				const ua = req.headers['user-agent'] || '';
				if (ua.length === 0) return false;
				const isSocial = SOCIAL_BOTS.test(ua)
					, isOther = OTHER_BOTS.test(ua);
				return isSocial || isOther
			}},
			isIPInternal: {value: function isIPInternal() { return isLocal(this.ip) }},
			params: { value: new URLSearchParams(search) }
		})
	}

	static enhanceRes(res, server) {
		return Object.defineProperties(res, {
			_server: { value: server },
			// cookie: {value: function cookie(name, domain) {
			// 	this.setHeader('Set-Cookie', )
			// }},
			defer: {value: function defer() {
				this._timeout && (clearTimeout(this._timeout), delete this._timeout);
				Object.defineProperty(this, 'deferred', { value: true });
				return true
			}},
			downloadFile: {value: async function downloadFile(path) {
				if (existsSync(path)) {
					this.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(basename(path))}"`);
					const { size } = await stat(path);
					this.setHeader('Content-Length', size);
				}

				this.sendFile(path)
			}, writable: true},
			// redirect: {value: function redirect(url) {
			// 	this.writeHead(307, { Location: url })
			// }},
			reject: {value: function reject() {
				const { data, status } = parseStatus(...arguments);
				if (status < 400) throw new RangeError("Invalid status code: " + status + ". Rejection code must be greater than or equal to 400");
				this.sendStatus(status, data)
			}},
			resolve: {value: function resolve() {
				const { data, status } = parseStatus(...arguments);
				if (status >= 400) throw new RangeError("Invalid status code: " + status + ". Resolution code must be smaller than 400");
				this.sendStatus(status, data)
			}},
			send: {value: function send(data) { this.resolve(200, data) }},
			sendDefault: {value: function sendDefault(options = {}) {
				const { headers, method, url } = this.req;
				switch (method) {
				case 'GET': {
					const domainFolder = headers.subdomain ? headers.subdomain + '.' + (options.host || headers.host) : 'public';
					try { this.sendFile(`${domainFolder}${url.replace(/\/$/, '')}${/\.\w*$/.test(url) ? '' : '/index.html'}`) }
					catch(err) {
						console.warn('Failed to handle GET', err);
						!this.finished && this.reject(500, 'Internal Server Error')
					}
				} break;
				case 'HEAD':
				case 'OPTIONS': this.writeHead(200).end(); break;
				default: this.writeHead(404).end()
				}
			}},
			sendFile: {value: function sendFile(path) {
				if (domainify.test(path)) path = domainify.call(this.req, path);
				let contentType = /* mimeTypes.parse(path); // */ mimeTypes[extname(path).toLowerCase()];
				if (!contentType) return this.reject(415, `Sorry, file extension ${extname(path)} is not currently supported.`);
				if (contentType.startsWith('image')) return this.sendImage(path);

				// let referer = URL.canParse(this.req.headers.referer) && new URL(this.req.headers.referer);
				// let relativePath = (this.req.headers.subdomain ? this.req.headers.host : 'public') + (referer && (await stat((this.req.headers.subdomain ? this.req.headers.host : 'public') + referer.pathname).isDirectory() ? referer.pathname.replace(/\/?$/, '/') : dirname(referer.pathname))) + this.req.url.replace(/^\//, '');
				// referer &&  && (routeUrl += dirname(referer.pathname))

				// get absolute/relative path
				// let cwd = process.cwd().replace(/\\/g, '/') + '/';
				// path = path.replace(new RegExp('^(' + cwd + ')?'), cwd);

				if (!existsSync(path)) {
					contentType = 'text/plain';
					path = 'public/404.html';
					if (!existsSync(path)) return this.reject(404, 'Error: File Not Found');
				}

				this.statusCode = 200;
				this.setHeader('Content-Type', contentType);

				// const fileStream = createReadStream(path)
				// 	, transformStream = Pipeline._stream(this.req, this, contentType);
				// fileStream.pipe(transformStream).pipe(this);
				const fileStream = createReadStream(path);
				fileStream.pipe(this);
				fileStream.on('error', err => {
					console.error(err);
					if (!this.headersSent) {
						this.statusCode = 500;
						this.end('Error reading the file');
					} else {
						this.destroy(err)
					}
				});

				this.on('close', () => fileStream.destroy())
			}, writable: true},
			sendImage: {value: async function sendImage(path) {
				const ext = extname(path)
					, contentType = mimeTypes[ext];
				if (!existsSync(path)) {
					path = path.replace(ext, '');
					const dir = dirname(path);
					if (existsSync(dir)) {
						const files = await readdir(dir).then(files =>
							files.filter(basename =>
								mimeTypes[extname(basename)]?.startsWith('image/')
							)
						);
						path = dir + '/' + files.find(file => basename(file, extname(file)) === basename(path));
					}
				}

				if (!existsSync(path)) return this.reject(404, 'Error: File Not Found');
				this.statusCode = 200;
				this.setHeader('Content-Type', contentType);

				let stream = createReadStream(path);
				// if (!['.ico', '.svg'].includes(ext)) {
				// 	const imageOptimizationStream = sharp({ failOn: 'none' });
				// 	if (this.req.searchParams?.has('size')) {
				// 		const targetSize = parseInt(this.req.searchParams.get('size'));
				// 		isFinite(targetSize) && imageOptimizationStream.resize(targetSize);
				// 	}

				// 	let targetExt = extname(this.req.url);
				// 	if (targetExt !== extname(path) && typeof imageOptimizationStream[targetExt = targetExt.slice(1)] == 'function') imageOptimizationStream[targetExt]({ force: true, nearLossless: true });
				// 	stream = stream.pipe(imageOptimizationStream);
				// }

				stream.pipe(this);
				stream.on('error', err => {
					console.error(err);
					if (!this.headersSent) {
						this.statusCode = 500;
						this.end('Error reading the file');
					} else {
						this.destroy(err)
					}
				});
				this.on('close', () => stream.destroy())
			}, writable: true},
			sendStatus: {value: function sendStatus(status, data) {
				let contentType = "text/plain";
				if (typeof data == 'object') {
					contentType = "application/json";
					data = JSON.stringify(data);
				}

				const headers = data && { 'Content-Type': contentType };
				data && (headers['Content-Length'] = Buffer.byteLength(data));
				this.writeHead(status, headers).end(this.req.method !== 'HEAD' && data)
			}}
		})
	}
}

const parseRelativePath = Object.defineProperties(function parseRelativePath(path, referer) {
	URL.canParse(referer) && (referer = URL.parse(referer).pathname);
	/\.\w+$/.test(referer) && (referer = referer.replace(basename(referer), ''));
	let dir = referer.replace(/\/?$/, '/');
	let out = 0;
	path = path.replace(/\.{1,2}\//g, escape => {
		escape.match(/^\.{2}\/$/) && out++;
		return ''
	});
	out > 0 && (dir = dir.replace(/^\/|\/$/g, '').split('/').slice(out).join('/').replace(/^\/?|\/?$/g, '/'));
	return dir + path
}, {
	regex: {
		value: /^[^\/]/,
		writable: true
	},
	test: {
		value: function test(path) {
			console.log(path, this.regex, String.prototype.match.call(path, this.regex), path.match(this.regex))
			return String.prototype.match.call(path, this.regex)
		},
		writable: true
	}
});

function resolveRelativePath(requestedPath, referer) {
	let refererDir = referer ? new URL(referer).pathname : '/';
	if (refererDir.endsWith('/')) refererDir += 'index.js'; // fallback
	return parseRelativePath(requestedPath, refererDir)
}

function pathify(path, { temporary } = {}) {
	if (domainify.test(path)) path = '//' + domainify.call(this, path);
	if (temporary) {
		let returnPath = '';
		const isSameDomain = !path.startsWith('//');
		if (!isSameDomain) {
			returnPath += encodeURI('http://' + this.headers.host + this.url.replace(/\/$/, ''));
		} else if (this.url !== '/') {
			returnPath += encodeURI(this.url);
		}

		returnPath && (path += '?return=' + returnPath);
	}

	return path
}

const subdomainDirs = readdirSync(process.cwd()).filter(d => /^\w+\..*$/.test(d))
	, subdomainRegex = /^(\w+\.)\//;
function domainify(path) {
	// For functionality in localhost
	return path.replace(subdomainRegex, m => subdomainDirs.find(d => d.startsWith(m.slice(0, -1))) + '/')
	// return path.replace(subdomainRegex, '$1' + this.headers.domain + '/')
}

Object.defineProperty(domainify, 'test', { value: path => subdomainRegex.test(path) });

const parseStatus = (status, data) => {
	const defaultStatus = 501;
	status ??= defaultStatus;
	if (typeof status == 'object') {
		data = status;
		status = data.code ?? data.status ?? data.statusCode ?? defaultStatus;
	}

	return { data, status }
};

function parseMultipartFormData(rawData, boundary) {
	const parts = [];
	const boundaryBytes = Buffer.from(`--${boundary}`);
	const endBoundaryBytes = Buffer.from(`--${boundary}--`);

	let startIndex = rawData.indexOf(boundaryBytes) + boundaryBytes.length;
	let endIndex = rawData.indexOf(boundaryBytes, startIndex);

	while (endIndex !== -1) {
		const part = rawData.slice(startIndex, endIndex);
		parts.push(parsePart(part));
		startIndex = endIndex + boundaryBytes.length;
		endIndex = rawData.indexOf(boundaryBytes, startIndex);
	}

	// Handling last part (which ends with --boundary--)
	const lastPart = rawData.slice(startIndex, rawData.length - endBoundaryBytes.length);
	if (lastPart.length > 0) {
		parts.push(parsePart(lastPart));
	}

	return parts
}

function parsePart(partData) {
	const headersEndIndex = partData.indexOf('\r\n\r\n')
		, headersRaw = partData.slice(0, headersEndIndex).toString()
		, body = partData.slice(headersEndIndex + 4) // Body starts after "\r\n\r\n"
		, headers = parseHeaders(headersRaw)
		, part = Object.defineProperty({
			headers,
			fieldName: headers['content-disposition'].match(/name="([^"]+)"/)[1],
			fileName: headers['content-disposition'].match(/filename="([^"]+)"/)?.[1],
			data: body
		}, 'file', { value: null, writable: true });

	if (part.fileName) {
		part.file = Object.defineProperty(new File([part.data], part.fileName), 'data', {
			value: part.data,
			writable: true
		});
	}

	return part
}

function parseHeaders(headersRaw) {
	const headers = {}
		, headerLines = headersRaw.split('\r\n');
	for (const line of headerLines) {
		const [key, value] = line.split(': ');
		if (key && value) {
			headers[key.toLowerCase()] = value;
		}
	}
	return headers
}

function parseCookieHeader(cookie) {
	const cookies = new Map();
	if (cookie) {
		const parts = cookie.split(/;\s*/g);
		for (const part of parts) {
			const [key, ...parts] = part.split('=');
			cookies.set(key, parts.join('='));
		}
	}

	return cookies
}

import { networkInterfaces } from "os";

function parseIPv4(ip) {
	if (!ip) return null;
	if (ip.startsWith("::ffff:")) ip = ip.slice(7); // IPv6-mapped IPv4
	const parts = ip.split(".").map(Number);
	if (parts.length !== 4 || parts.some(n => n < 0 || n > 255)) return null;
	return new Uint8Array(parts)
}

const localSubnets = (nets => {
	const subnets = [{ base: new Uint8Array([127, 0, 0, 1]), maskLength: 32 }];
	for (const name of Object.keys(nets)) {
		for (const net of nets[name]) {
			if (net.family !== 'IPv4' || net.internal) continue;
			const base = new Uint8Array(net.address.split('.').map(Number))
				, maskParts = net.netmask.split('.').map(Number);
			let maskLength = 0;
			for (const octet of maskParts) {
				for (let i = 7; i >= 0; i--)
					if ((octet & (1 << i)) !== 0) maskLength++;
			}

			subnets.push({ base, maskLength });
		}
	}

	return subnets
})(networkInterfaces());
function ipInSubnet(ipBytes, { base, maskLength }) {
	const fullBytes = Math.floor(maskLength / 8)
		, remainingBits = maskLength % 8;
	for (let i = 0; i < fullBytes; i++) if (ipBytes[i] !== base[i]) return false;
	if (remainingBits > 0) {
		const mask = 0xFF << (8 - remainingBits);
		if ((ipBytes[fullBytes] & mask) !== (base[fullBytes] & mask)) return false;
	}

	return true;
}

function isLocal(ip) {
	if (!ip) return false;
	if (ip === "127.0.0.1" || ip === "::1") return true;

	const ipBytes = parseIPv4(ip);
	if (!ipBytes) return false;

	return localSubnets.some(subnet => ipInSubnet(ipBytes, subnet))
}