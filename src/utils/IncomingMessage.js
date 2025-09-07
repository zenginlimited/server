import EventEmitter from "events";
import { realpath } from "fs/promises";
import { extname, resolve, sep } from "path";

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

export default class IncomingMessage extends EventEmitter {
	authority = null;
	// body = null;
	cookies = new Map();
	headers = null;
	method = 'GET';
	ip = null;
	params = new URLSearchParams;
	path = null;
	scheme = null;
	constructor(server, stream, headers) {
		super();
		Object.defineProperties(this, {
			aborted: { value: false, writable: true },
			server: { value: server },
			stream: { value: stream }
		});
		this.authority = headers[':authority'];
		this.cookies = parseCookieHeader(headers.cookie);
		this.headers = headers;

		// let ip = headers['cf-pseudo-ipv4'] || headers['cf-connecting-ip'] || headers['x-forwarded-for'] || stream.session.socket.remoteAddress || null;
		// if (ip) {
		// 	if (ip.includes(',')) ip = ip.split(',')[0].trim();
		// 	if (ip.startsWith('::ffff:')) ip = ip.slice(7);
		// }

		this.ip = stream.session.socket.remoteAddress;
		Object.defineProperty(this, 'ipv4', { value: parseIPv4(this.ip) });
		this.method = headers[':method'];

		let search = null;
		this.path = headers[':path'].replace(/\?.*/, match => {
			search = match;
			return ''
		});
		this.params = new URLSearchParams(search);

		// try { this.path = decodeURIComponent(this.path) }
		// catch (error) { return this.emit('error', new Error("Malformed URI: " + this.path) }

		stream.on('aborted', () =>
			Object.defineProperty(this, 'aborted', { value: true, writable: false })
		);
	}

	// async filePath() {
	// 	await jailPath(subdomain ? (options.hostname ? subdomain + '.' + options.hostname : req.headers.host) : this.root, req.path, extname(req.path) ? '' : 'index.html')
	// }

	isBot() {
		const SOCIAL_BOTS = /(facebookexternalhit|Discordbot|Twitterbot|LinkedInBot|WhatsApp)/i
			, OTHER_BOTS = /(Googlebot|bingbot|DuckDuckBot|Slurp|YandexBot)/i;
		const ua = this.headers['user-agent'] || '';
		if (ua.length === 0) return false;
		const isSocial = SOCIAL_BOTS.test(ua)
			, isOther = OTHER_BOTS.test(ua);
		return isSocial || isOther
	}

	isIPInternal() {
		return isLocal(this.ip)
	}
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