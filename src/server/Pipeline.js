import { Transform } from 'stream';

export default class Pipeline {
	#hasGeneratorPipes = false;
	#hasAsyncGeneratorPipes = false;
	#pipes = [];
	#typedPipeline = new Map();
	async #runPipe(pipe, chunk, ...args) {
		switch (pipe.constructor.name) {
			case 'AsyncGeneratorFunction': for await (const c of pipe(chunk, ...args)) chunk = c ?? chunk; break;
			case 'AsyncFunction': chunk = await pipe(chunk, ...args); break;
			case 'GeneratorFunction': for (const c of pipe(chunk, ...args)) chunk = c ?? chunk; break;
			default: chunk = pipe(chunk, ...args)
		}
		return chunk
	}

	async #runPipes(chunk, req, res, contentType) {
		const typed = this.#typedPipeline.get(contentType);
		if (this.#hasAsyncGeneratorPipes || this.#hasGeneratorPipes) {
			for (const p of this.#pipes) chunk = await this.#runPipe(p, chunk, req, res);
			if (typed) for (const p of typed) chunk = await this.#runPipe(p, chunk, req, res);
		} else {
			for (const p of this.#pipes) chunk = await p(chunk, req, res) ?? chunk;
			if (typed) for (const p of typed) chunk = await p(chunk, req, res) ?? chunk;
		}

		return chunk
	}

	_process(data, req, res, contentTypeOverride) {
		const contentType = contentTypeOverride || res.getHeader('Content-Type') || '';
		return this.#runPipes(data, req, res, contentType)
	}

	_stream(req, res, contentTypeOverride) {
		const contentType = contentTypeOverride || res?.getHeader('Content-Type') || '';
		return new Transform({
			transform: async (chunk, encoding, callback) => {
				try {
					const result = await this.#runPipes(chunk.toString('utf8'), req, res, contentType);
					callback(null, result);
				} catch (err) {
					callback(err);
				}
			}
		})
	}

	addPipe(pipe, accept) {
		if (typeof pipe != 'function') throw new TypeError('pipe must be of type: Function');
		if (!accept || accept.length === 0) {
			this.#pipes[this.#pipes.length] = pipe;
			return;
		}

		const set = new Set((typeof accept == 'string' ? [accept] : accept).map(t => t.toLowerCase()));
		Object.defineProperty(pipe, 'accept', { value: Object.freeze(set) });

		for (const type of set) {
			let arr = this.#typedPipeline.get(type);
			if (!arr) {
				arr = [];
				this.#typedPipeline.set(type, arr);
			}
			arr[arr.length] = pipe;
		}

		switch (pipe.constructor.name) {
			case 'AsyncGeneratorFunction': this.#hasAsyncGeneratorPipes = true; break;
			case 'GeneratorFunction': this.#hasGeneratorPipes = true
		}
	}

	addHTMLPipe(pipe) {
		this.addPipe(pipe, 'text/html')
	}

	addJSONPipe(pipe) {
		this.addPipe(pipe, 'application/json')
	}

	addStream(stream) {
		throw new Error('Not implemented')
	}
}