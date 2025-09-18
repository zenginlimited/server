import AbstractServer from "./AbstractServer.js";
import { createReadStream, existsSync, readdirSync } from "fs";
import { readdir, realpath, stat } from "fs/promises";
import { Server as Server } from "http";
import { Server as SecureServer } from "https";
import { isIP } from "net";
import { basename, dirname, extname, matchesGlob, resolve, sep } from "path";
import mimeTypes from "../utils/mimeTypes.js";

const JAIL_ROOT = process.cwd()
	, testPath = p => p.slice(1) === JAIL_ROOT.slice(1) || p.slice(1).startsWith(JAIL_ROOT.slice(1) + sep);
const safeJoinCap = (...args) => {
	const safeArgs = args.map(a => a.replace(/^[/\\]+/, ''))
		, resolved = resolve(JAIL_ROOT, ...safeArgs);
	if (!testPath(resolved)) return JAIL_ROOT;
	return resolved
};
const jailPath = async (...args) => {
	const resolved = safeJoinCap(...args);
	try {
		const real = await realpath(resolved);
		if (!testPath(real)) throw new RangeError('Path traversal detected');
		return real;
	} catch (err) { if (err.code !== 'ENOENT') throw err }
	return resolved
};

const SOCIAL_BOTS = /(facebookexternalhit|Discordbot|Twitterbot|LinkedInBot|WhatsApp)/i
	, OTHER_BOTS = /(Googlebot|bingbot|DuckDuckBot|Slurp|YandexBot)/i;

export default class WebServer extends AbstractServer {
	#rateLimits = new Map;
	#requests = {};

	constructor(options) {
		options = Object.assign({
			keepAlive: true,
			noDelay: true
		}, options, options?.ssl);
		delete options.ssl;
		super(...arguments);
		Object.defineProperty(this, '_server', { value: new (options.ssl ? SecureServer : Server)(options, async (req, res) => {
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
			this.constructor.enhanceRes(res, this.pipeline);

			if (this._conditions.length > 0) {
				const results = await Promise.all(this._conditions.map(c => c(req, res)));
				if (!results.every(Boolean)) return;
			}

			for (const condition of this._conditions) {
				if (!await condition(req, res)) return;
			}

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
							if (contentType?.startsWith('application/octet-stream')) return resolve(body);
							try {
								if (contentType?.startsWith('multipart/form-data')) {
									const boundary = /boundary=(.+)/.exec(contentType)?.[1] || body.toString('utf8').match(/(?<=^--)[^\n\r]+/)?.[0];
									if (!boundary) throw new Error('Boundary not found');

									const parts = parseMultipartFormData(body, boundary)
										, multipartBody = Object.defineProperty({ files: [] }, 'parts', { value: parts, writable: true });
									for (const part of parts) {
										if (part.fileName && multipartBody.files.push(part.file)) {
											multipartBody[part.fieldName] = part.file; continue;
										}
										multipartBody[part.fieldName] = part.data.toString().replace(/\r\n$/, '');
									}

									resolve(multipartBody);
								} else if (body.length > 0) {
									resolve(JSON.parse(body.toString()));
								}
							} catch (err) { reject(err) }
							resolve(null)
						})
					});
				} catch(err) {
					return res.reject(400, { error: err.message });
				}
			}

			req.isBot() && console.log('[CRAWLER DETECTED]', req.headers['user-agent']);

			const isRouteProtected = this._isProtected(req.url, { subdomain });
			if (isRouteProtected) {
				let authorization = req.headers.authorization || (isRouteProtected.cookie && req.cookies.get(isRouteProtected.cookie))
					, redirectPath = isRouteProtected.authRedirect;
				if ((!authorization || !this._authenticate(authorization, isRouteProtected)) && (!redirectPath || req.url !== redirectPath) && (!isRouteProtected.authEndpoint || !req.url.startsWith(isRouteProtected.authEndpoint))) {
					if (redirectPath) {
						// let returnPath = '';
						// req.url !== '/' && (returnPath += '?return=' + encodeURI(req.url));
						return res.writeHead(302, { 'Location': pathify.call(req, redirectPath, { temporary: true }) /* redirectPath + returnPath */ }).end();
					}

					return res.writeHead(401, { 'WWW-Authenticate': `Basic realm="${options.host || 'App'}"` }).end();
				}
			}

			Object.defineProperty(req, 'filePath', { value: await jailPath(subdomain ? (options.host ? subdomain + '.' + options.host : req.headers.host) : this.root, req.url, extname(req.url) ? '' : 'index.html'), writable: true });
			if (req.query.has('download')) return res.downloadFile(req.filePath);
			Object.defineProperties(req, {
				actualPath: { value: req.filePath, writable: true },
				dirPath: { value: req.filePath.replace(basename(req.filePath), ''), writable: true }
			});

			// const saveData = 'on' === req.headers['save-data'];
			const route = this._route(req.method, (subdomain !== null ? `${subdomain}.` : '') + req.url);
			if (typeof route == 'function') {
				if (route.params) {
					Object.defineProperty(req, 'params', { value: {}, writable: false });
					const [_, ...params] = route.regex.exec((subdomain !== null ? `${subdomain}.` : '') + req.url);
					if (params) for (const p in params) req.params[route.params[p]] = params[p];
				}

				// Request timeout
				// res.setTimeout(10e3, () => !res.deferred && !res.finished && res.writeHead(408).end());
				Object.defineProperty(res, '_timeout', {
					configurable: true,
					value: setTimeout(() => !res.finished && !res.headersSent && res.writeHead(408).end(), 10e3)
				});
				try {
					let result = route(req, res);
					if (result instanceof Promise) result = await result;
					if (result !== false || res.finished) return;
					if (/* options.resolveReturnValue && */ result) res.resolve(result);
				} catch (err) {
					res.finished || res.reject(500, 'Internal Server Error');
					if (this.listenerCount('error') === 0) throw err;
					return this.emit('error', err);
				}
			}

			res.continue()
		}), writable: true })
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
			query: { value: new URLSearchParams(search) }
		})
	}

	static enhanceRes(res, pipeline = null) {
		return Object.defineProperties(res, {
			continue: {value: function respond(options = {}) {
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
			// 	this.writeHead(307, { Location: url }).end()
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
			sendFile: {value: async function sendFile(path) {
				if (domainify.test(path)) path = domainify.call(this.req, path);
				let contentType = /* mimeTypes.parse(path); // */ mimeTypes[extname(path).toLowerCase()];
				if (!contentType) return this.reject(415, `Sorry, file extension ${extname(path)} is not currently supported.`);
				if (contentType.startsWith('image') && !existsSync(path)) {
					path = path.replace(extname(path), '');
					const dir = dirname(path);
					if (existsSync(dir)) {
						const files = await readdir(dir).then(files =>
							files.filter(basename =>
								mimeTypes[extname(basename)]?.startsWith('image/')
							)
						);
						path = dir + '/' + files.find(file => basename(file, extname(file)) === basename(path));
						this.req.actualPath = path;
					}
				}

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

				let fileStream = createReadStream(path);
				if (pipeline) {
					const transformStream = pipeline._stream(this.req, this, contentType);
					fileStream = fileStream.pipe(transformStream);
				}

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
	const parts = []
		, boundaryBytes = Buffer.from(`--${boundary}`)
		, endBoundaryBytes = Buffer.from(`--${boundary}--`);

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