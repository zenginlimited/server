import type EventEmitter from "events";
import type { IncomingMessage, ServerOptions, ServerResponse } from "http";
import type { Http2Server, Http2Stream } from "http2";
import type { Transform } from "stream";
import type { MIMEType } from "util";

//#region Classes
declare class Pipeline {
	addHTMLPipe(pipe: (html: string, req: IncomingMessage, res: ServerResponse) => string): void
	addJSONPipe(pipe: (data: object, req: IncomingMessage, res: ServerResponse) => object): void
	addPipe(pipe: (raw: string, req: IncomingMessage, res: ServerResponse) => string, mimeTypes: string[]): void
	addStream(stream: Transform): void
	addStreamFactory(factory: (req: IncomingMessage, res: ServerResponse) => Transform): void
}

declare class AbstractServer extends EventEmitter {
	static readonly Pipeline: Pipeline

	allowedMimeTypes: MIMEType[]
	readonly options: WebServerOptions
	pipeline: Pipeline
	root: string

	constructor(options: AbstractServerOptions)

	addCondition(callback: (req: IncomingMessage, res: ServerResponse) => boolean): void
	auth(path: string | string[], callback: (token: string) => boolean | Promise<boolean>): void
	delete(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
	get(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
	head(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
	patch(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
	post(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
	protect(path: string | string[], callback: (token: string) => void): void
	protect(path: string | string[], config: object, callback: (token: string) => boolean | Promise<boolean>): void
	put(path: string | string[], callback: (req: IncomingMessage, res: ServerResponse) => void): void
}

declare class Http2IncomingMessage {
	aborted: boolean
	authority: string
	// body: Buffer?
	cookies: Map<string, boolean | string>
	headers: Object // Headers
	method: RequestMethod
	ip: string
	readonly ipv4: Uint8Array | null
	params: URLSearchParams
	path: string
	scheme: string
	readonly server: Http2Server
	readonly stream: Http2Stream

	isBot(): boolean
	isIPInternal(): boolean
}

declare class Http2ServerResponse {
	readonly deferred: boolean
	readonly headers: Headers
	readonly headersSent: boolean
	readonly req: Http2IncomingMessage
	readonly server: Http2Server
	status: number | null
	readonly stream: Http2Stream

	// cookie(key: string, value: string, options?: object): void
	// cors(): void
	defer(): boolean
	downloadFile(path: string): void
	end(data?: string): void
	redirect(url: string, status?: number)
	reject(status: number, data?: string | Object): void
	resolve(status: number, data?: string | Object): void
	send(data: string | Object): void
	sendDefault(): void
	sendFile(path: string): void
	sendStatus(status: number, data?: string | Object): void
	writeHead(status?: number, headers: Headers | Map<string, string> | Object<string, string>): Http2ServerResponse
}

declare class WebServer extends AbstractServer {
	constructor(options: WebServerOptions)

	static enhanceReq(req: IncomingMessage): IncomingMessage
	static enhanceRes(res: ServerResponse, pipeline: Pipeline): ServerResponse
}

declare class Http2Server extends AbstractServer {
	constructor(options: WebServerOptions)

	addCondition(callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => boolean): void
	delete(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
	get(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
	head(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
	patch(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
	post(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
	put(path: string | string[], callback: (req: Http2IncomingMessage, res: Http2ServerResponse) => void): void
}
//#endregion

//#region Interfaces
interface AbstractServerOptions extends ServerOptions {
	hostname?: string,
	port: string,
	redirectHTTP: boolean
}

interface WebServerOptions extends AbstractServerOptions {
	// http?: ServerOptions,
	// https?: SecureServerOptions,
	ssl: {
		ca: Buffer,
		cert: Buffer,
		key: Buffer
	}
}
//#endregion

//#region Enumerations
declare enum RequestMethod {
	Delete = 'DELETE',
	Get = 'GET',
	Head = 'HEAD',
	Options = 'OPTIONS',
	Post = 'POST',
	Put = 'PUT'
}
//#endregion

//#region Exports
export { Pipeline, Http2Server, Http2IncomingMessage as IncomingMessage, Http2ServerResponse as ServerResponse, WebServer }
export type { AbstractServerOptions, WebServerOptions }
export { RequestMethod }
export default Http2Server