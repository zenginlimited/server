import EventEmitter from "events";
import { realpath } from "fs/promises";
import { createServer } from "http";
import { /* matchesGlob, */ resolve, sep } from "path";
import mimeTypes from "../utils/mimeTypes.js";
import Pipeline from "./Pipeline.js";

export default class AbstractServer extends EventEmitter {
	static Pipeline = Pipeline;

	#protected = new Map;
	#routes = new Map;

	allowedMimeTypes = Object.assign({}, mimeTypes);
	pipeline = new Pipeline;
	root = 'public';

	/**
	 * 
	 * @param {Object} [options]
	 * @param {string} [options.hostname]
	 * @param {boolean} [options.redirectHTTP]
	 * @param {Function} [callback]
	 */
	constructor(options = {}, ...args) {
		super();
		Object.defineProperties(this, {
			_conditions: {value: []},
			bind: {value: function bind() {
				this._server.listen(...arguments);
				const callback = args.at(-1) || options;
				if (typeof callback == 'function') callback();
				if (!options.redirectHTTP) return;
				const { /* address, */ port } = this._server.address();
				if (port === 80) return;
				Object.defineProperty(this, '_redirectServer', {
					value: createServer({
						keepAlive: false,
						maxHeadersCount: 200,
						noDelay: true
					}, (req, res) => {
						const host = /* options.hostname || */ req.headers.host?.split(':')[0];
						res.writeHead(307, { Location: `https://${host}:${port}${req.url}` }).end()
					}).listen(80, /* address */ '0.0.0.0')
				});
				this._redirectServer.maxConnections = 1e4;
				this._redirectServer.timeout = 1e3;
				this._redirectServer.keepAliveTimeout = 0
			}},
			options: {value: options || {}}
		})
	}

	#glob(path) {
		if (path.includes('?')) path = path.replace(/\?$/g, '.');
		if (path.includes('*')) {
			path = path.replace(/(?<!\*)(\*)(?!\*)/g, '[^/]$1');
			if (path.includes('**')) path = path.replace(/(\*){2}/g, '.$1');
		}
		if (path.includes('[!')) path = path.replace(/(?<=\[)(\!)(?=.+\])/g, '^');
		// match :id wildcard options
		if (path.includes('/:')) path = path.replace(/:[^\/]+/g, '[^/]+');
		return path
	}

	#isPathInsideRoot(path) {
		const rootPath = this.root.replace(/^[/\\]+/, '');
		return path.slice(1) === rootPath || path.slice(1).startsWith(rootPath + sep);
	}

	#saveRoute(method, path, callback, exceptions) {
		if (typeof path != 'string' && !(path instanceof RegExp)) {
			if (!Array.isArray(path)) throw new TypeError("Path must be of type: string");
			for (const p of path) this.#saveRoute(method, p, callback, exceptions);
			return;
		}
		if (typeof callback != 'function') throw new TypeError("Callback must be of type: function");
		if (!this.#routes.has(method)) this.#routes.set(method, new Map);
		if (typeof exceptions == 'object' && exceptions !== null) {
			Object.defineProperty(callback, 'exceptions', {
				value: Object.values(exceptions).map(path => {
					const glob = this.#glob(path);
					return glob !== path ? new RegExp(`^${glob}$`) : path
				}),
				writable: true
			});
		}

		if (typeof path == 'string') {
			if (path.includes('/:')) {
				const params = [];
				let glob = path;
				if (glob.includes('.')) glob = glob.replace('.', '\\.');
				const partial = glob.replace(/:([^\/]+)/g, (_, param) => {
					params.push(param);
					return '([^/]+)'
				});
				const regex = new RegExp(`^${partial}$`);
				Object.defineProperties(callback, {
					params: { value: Object.freeze(params) },
					regex: { value: regex }
				});
				path = regex;
			} else {
				const glob = this.#glob(path);
				if (glob !== path) path = new RegExp(`^${glob}$`);
			}
		}

		this._route(method).set(path, callback)
	}

	_authenticate(authorization, config) {
		const match = /\S+$/.exec(authorization)?.[0];
		return config.authCallback && config.authCallback(match)
	}

	_isProtected(path, { subdomain } = {}) {
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

	_route(method, path) {
		const route = this.#routes.get(method);
		if (!route) return null;
		if (!path) return route;
		let match = route.get(path);
		if (!match) {
			const globs = Array.from(route.keys()).filter(route => route instanceof RegExp).sort((a, b) => b.source.length - a.source.length)
				, glob = globs.find(glob => glob.test(path) /* Match everything, and I mean everything */ /* matchesGlob(path, rout) */);
			if (glob) {
				const globMatch = route.get(glob)
					, matchesException = globMatch.exceptions?.find(glob => typeof glob == 'string' ? glob === path : glob.test(path));
				if (!matchesException) match = route.get(glob);
			}
		}

		return match || route.get('*')
	}

	/**
	 * 
	 * @param {Function} callback
	 */
	// before() {
	addCondition(callback) {
		if (typeof callback != 'function') throw new TypeError("Callback must be of type: function");
		if (this._conditions.includes(callback) !== -1) throw new Error("This condition has already been added!");
		this._conditions.push(callback)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	auth(path, callback) {
		if (typeof path != 'string') throw new TypeError("Path must be of type: string");
		if (typeof callback != 'function') throw new TypeError("Callback must be of type: function");
		this.#protected.set(path, Object.assign({ authCallback: callback }, this.#protected.get(path)))
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	delete(path, callback) {
		return this.#saveRoute('DELETE', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	get(path, callback) {
		return this.#saveRoute('GET', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	head(path, callback) {
		return this.#saveRoute('HEAD', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	patch(path, callback) {
		return this.#saveRoute('PATCH', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	post(path, callback) {
		return this.#saveRoute('POST', ...arguments)
	}

	/**
	 * 
	 * @param {string} path
	 * @param {Function} callback
	 */
	pre(path, callback) {
		return this.#saveRoute('PRE', ...arguments)
	}

	/**
	 * Protect a file or directory
	 * @param {(string|string[])} path
	 * @param {Object} [config]
	 * @param {Function} config.authCallback
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
	 * @param {Function} callback 
	 */
	put(path, callback) {
		return this.#saveRoute('PUT', ...arguments)
	}

	resolvePathWithinRoot(...segments) {
		const sanitized = segments.map(s => s.replace(/^[/\\]+/, ''))
			, resolved = resolve(this.root, ...sanitized);
		if (!this.#isPathInsideRoot(resolved)) return this.root;
		return resolved
	}

	async resolveRealPathWithinRoot(...segments) {
		const resolved = this.resolvePathWithinRoot(...segments);
		try {
			const real = await realpath(resolved);
			if (!this.#isPathInsideRoot(real)) throw new RangeError('Path traversal detected');
			return real;
		} catch (err) {
			if (err.code !== 'ENOENT') throw err;
		}
		return resolved
	}

	// start() {}
}