import { IncomingMessage, ServerResponse } from "http";
import { Transform } from "stream";
import Pipeline from "../src/server/Pipeline";
import WebServer from "../src/server/WebServer";

//#region Classes
export declare class Pipeline {
	addHTMLPipe(pipe: (req: IncomingMessage, res: ServerResponse) => void): Pipeline
	addJSONPipe(pipe: (req: IncomingMessage, res: ServerResponse) => void): Pipeline
	addPipe(pipe: (req: IncomingMessage, res: ServerResponse) => void, mimeTypes: string[]): Pipeline
	addStream(stream: Transform): Pipeline
}

declare class WebServer {
	static readonly Pipeline: Pipeline

	auth(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	delete(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	get(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	head(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	patch(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	post(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void
	protect(path: string, config: object, callback: (authorization: string) => void): void
	put(path: string, callback: (req: IncomingMessage, res: ServerResponse) => void): void

	static enhanceReq(req: IncomingMessage): IncomingMessage
	static enhanceRes(res: ServerResponse): ServerResponse
}
export default WebServer;
//#endregion