import { extname } from "path"

export const mimeTypes = Object.defineProperty({
	'.html': 'text/html',
	'.js': 'text/javascript',
	'.css': 'text/css',
	'.txt': 'text/plain',
	'.json': 'application/json',
	'.png': 'image/png',
	'.jpg': 'image/jpg',
	'.jpeg': 'image/jpg',
	'.gif': 'image/gif',
	'.svg': 'image/svg+xml',
	'.webp': 'image/webp',
	'.ico': 'image/x-icon',
	'.ogg': 'audio/ogg',
	'.wav': 'audio/wav',
	'.mov': 'video/mov',
	'.mp4': 'video/mp4',
	'.pdf': 'application/pdf',
	'.woff': 'application/font-woff',
	'.ttf': 'application/font-ttf',
	'.eot': 'application/vnd.ms-fontobject',
	'.otf': 'application/font-otf',
	'.wasm': 'application/wasm',
	'.xml': 'application/xml'
}, 'parse', {
	value: function parse(fileName) {
		return this[extname(fileName).toLowerCase()] || 'text/plain'
	}
});
export default mimeTypes;