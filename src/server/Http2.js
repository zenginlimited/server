import { randomUUID } from "crypto";
import { readdirSync } from "fs";
import { realpath } from "fs/promises";
import { createSecureServer } from "http2";
import { isIP } from "net";
import { basename, extname, matchesGlob, resolve, sep } from "path";
import AbstractServer from "./AbstractServer.js";
import IncomingMessage from "../utils/IncomingMessage.js";
import ServerResponse from "../utils/ServerResponse.js";

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

export default class WebServer extends AbstractServer {
	#rateLimits = new Map;
	#requests = {};

	constructor(options) {
		options = Object.assign({
			// allowHTTP1: true
		}, options, options?.ssl);
		delete options.ssl;
		if (options.cors) {
			const allowHeaders = new Set([/* 'Content-Type' */]);
			if (options.cors.allowCredentials) allowHeaders.add('Authorization');
			if (Array.isArray(options.cors.allowHeaders)) for (const header of options.cors.allowHeaders) allowHeaders.add(header);
			options.cors.allowHeaders = Array.from(allowHeaders).join(', ');
			if (Array.isArray(options.cors.allowMethods)) options.cors.allowMethods = Array.from(options.cors.allowMethods).join(', ');
		}

		super(...arguments);
		Object.defineProperty(this, '_server', { value: createSecureServer(options), writable: true });
		this._server.on('stream', async (stream, headers) => {
			const req = new IncomingMessage(this, stream, headers)
				, res = new ServerResponse(this, req, this.pipeline);
			options.debug && stream.on('close', () =>
				console.log(new Date(), `\x1b[3${2 - (req.aborted || res.status >= 400) + (res.status >= 300 && res.status < 400)}m${req.aborted ? '\x1b[9m' : ''}` + req.method + '\x1b[0m', res.status, (req.headers.subdomain ? `\x1b[2m${req.headers.subdomain}.\x1b[22m` : '') + req.path, `\x1b[2m${req.ip}\x1b[22m`)
			);

			if (this._conditions.length > 0) {
				const results = await Promise.all(this._conditions.map(c => c(req, res)));
				if (!results.every(Boolean)) return;
			}

			for (const condition of this._conditions) {
				if (!await condition(req, res)) return;
			}

			if (!req.isIPInternal() && this.#rateLimit(req)) {
				res.headers.set('retry-after', (60 - Math.floor((Date.now() - this.#rateLimits.get(req.ip)) / 1e3)));
				return res.reject(429, { message: "You're doing that too often! Try again in " + (60 - Math.floor((Date.now() - this.#rateLimits.get(req.ip)) / 1e3)) + " seconds." });
			}

			try { req.path = decodeURIComponent(req.path) }
			catch (error) {
				console.error(`Failed to decode "${req.path}":`, error);
				return res.reject(400, { message: "Malformed URI: " + req.path });
			}

			if (!req.isSameOrigin) {
				if (options.cors) {
					options.cors.allowCredentials && req.origin && res.headers.set('Access-Control-Allow-Credentials', true);
					options.cors.allowHeaders && res.headers.set('Access-Control-Allow-Headers', options.cors.allowHeaders);
					options.cors.allowMethods && res.headers.set('Access-Control-Allow-Methods', options.cors.allowMethods || 'GET');
					res.headers.set('Access-Control-Allow-Origin', req.origin || '*');
					res.headers.set('Access-Control-Max-Age', options.cors.maxAge ?? 2592e3); // 30 days
				}

				if (options.blockCrossFrames) {
					res.headers.set('Content-Security-Policy', "frame-ancestors 'self'");
					res.headers.set('X-Frame-Options', 'SAMEORIGIN');
				}
			}

			if (req.method === 'OPTIONS') return res.writeHead(204).end();

			// const referer = URL.canParse(req.headers.referer) ? new URL(req.headers.referer) : null
			// 	, refererHost = referer ? referer.host : null;
			// options.debug && console.log(req.path, 'Converted to relative path:', resolveRelativePath(req.path, req.headers.referer));

			Object.defineProperty(req.headers, 'subdomains', { value: [], writable: true });
			let subdomain = null;
			if (!isIP(req.authority) && req.authority) {
				let hostparts = req.authority.split(/\./g);
				if (hostparts.length > 2) {
					let subdomains = hostparts.slice(0, -2);
					subdomain = subdomains.join('.');
					req.headers.subdomains.push(...subdomains);
				}
			}

			options.forwardWWW && subdomain === 'www' && (subdomain = null);
			req.headers.subdomain = subdomain;
			req.headers.domain = req.authority?.replace(subdomain + '.', '');
			if (req.method === 'GET') {
				if (!req.isBot() && options.sessionTracking && !req.cookies.has('zl_session')) {
					res.cookie('zl_session', randomUUID(), {
						domain: `.${req.headers.domain}`,
						httpOnly: true,
						sameSite: 'Lax',
						secure: true
					});
				}
			} else if (req.method !== 'HEAD') {
				try {
					req.body = await new Promise((resolve, reject) => {
						const chunks = [];
						let length = 0;
						stream.on('error', reject);
						stream.on('data', chunk => {
							chunks.push(chunk);
							length += chunk.length;
							// if (length > process.env.MAX_REQUEST_BODY_LENGTH /* 1e6 */) {
							// 	req.destroy(); // prevent DOS
							// 	reject(new Error('Request body too large'));
							// }
						});
						stream.on('end', () => {
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

			const isRouteProtected = this._isProtected(req.path, { subdomain });
			if (isRouteProtected) {
				let authorization = req.headers.authorization || (isRouteProtected.cookie && req.cookies.get(isRouteProtected.cookie))
				  , redirectPath = isRouteProtected.authRedirect;
				if ((!authorization || !await this._authenticate(authorization, isRouteProtected)) && (!redirectPath || req.path !== redirectPath) && (!isRouteProtected.authEndpoint || !req.path.startsWith(isRouteProtected.authEndpoint))) {
					if (redirectPath) {
						// let returnPath = '';
						// req.path !== '/' && (returnPath += '?return=' + encodeURI(req.path));
						return res.redirect(pathify.call(req, redirectPath, { temporary: true }) /* redirectPath + returnPath */, 302);
					}

					return res.writeHead(401, { 'WWW-Authenticate': `Basic realm="${options.hostname || 'App'}"` }).end();
				}
			}

			Object.defineProperty(req, 'filePath', { value: await jailPath(subdomain ? (options.hostname ? subdomain + '.' + options.hostname : req.authority) : this.root, req.path, extname(req.path) ? '' : 'index.html'), writable: true });
			if (req.query.has('download')) return res.downloadFile(req.filePath);
			Object.defineProperties(req, {
				actualPath: { value: req.filePath, writable: true },
				dirPath: { value: req.filePath.replace(basename(req.filePath), ''), writable: true }
			});

			const pre = this._route('PRE', (subdomain !== null ? `${subdomain}.` : '') + req.path);
			if (typeof pre == 'function') {
				try {
					let result = pre(req, res);
					if (result instanceof Promise) result = await result;
					if (res.finished) return;
				} catch (err) {
					res.finished || res.reject(500, 'Internal Server Error');
					if (this.listenerCount('error') === 0) throw err;
					return this.emit('error', err);
				}
			}

			// const saveData = 'on' === req.headers['save-data'];
			const route = this._route(req.method, (subdomain !== null ? `${subdomain}.` : '') + req.path);
			if (typeof route == 'function') {
				if (route.params) {
					Object.defineProperty(req, 'params', { value: {}, writable: false });
					const [_, ...params] = route.regex.exec((subdomain !== null ? `${subdomain}.` : '') + req.path);
					if (params) for (const p in params) req.params[route.params[p]] = params[p];
				}

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

			res.continue(options)
		})
	}

	#rateLimit(req) {
		// only ignore if content type is octet stream in req or res, not accept
		if (req.headers.accept?.startsWith('application/octet-stream') || req.headers['content-type']?.startsWith('application/octet-stream')) return; // only whitelist chunked file upload paths?
		let requestCache = this.#requests[req.ip] ||= {};
		requestCache[req.path] = 1 + (requestCache[req.path] | 0),
		requestCache.timer && clearTimeout(requestCache.timer);
		Object.defineProperty(requestCache, 'timer', {
			value: setTimeout(() => delete this.#requests[req.ip], 8e3),
			writable: true
		});
		if (requestCache[req.path] > 33) {
			this.#rateLimits.set(req.ip, Date.now());
			requestCache.rateLimitTimer && clearTimeout(requestCache.rateLimitTimer);
			Object.defineProperty(requestCache, 'rateLimitTimer', {
				value: setTimeout(() => this.#rateLimits.delete(req.ip), 6e4),
				writable: true
			});
			delete requestCache[req.path];
		}

		return this.#rateLimits.has(req.ip)
	}

	// cors() {}
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
			returnPath += encodeURI(`${this.scheme || this.headers[':scheme']}://${this.authority}${this.path.replace(/\/$/, '')}`);
		} else if (this.path !== '/') {
			returnPath += encodeURI(this.path);
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