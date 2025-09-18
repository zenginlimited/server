import { PassThrough, Transform } from 'stream';

export default class Pipeline {
	#hasGeneratorPipes = false;
	#hasAsyncGeneratorPipes = false;
	#pipes = [];
	#streams = [];
	#streamFactories = [];
	#typedPipeline = new Map();
	get length() {
		return (
			this.#pipes.length +
			Array.from(this.#typedPipeline.values()).flat().length +
			this.#streams.length +
			this.#streamFactories.length
		)
	}

	#getApplicablePipes(contentType) {
		const typed = this.#typedPipeline.get(contentType);
		return [...this.#pipes, ...(typed || [])]
	}

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
		const contentType = contentTypeOverride || res.getHeader?.('Content-Type') || res.headers.get('content-type') || '';
		return this.#runPipes(data, req, res, contentType)
	}

	_stream(req, res, contentTypeOverride) {
		const streams = []
			, pipes = this.#getApplicablePipes(contentTypeOverride || res?.getHeader?.('Content-Type') || res?.headers.get('content-type') || '');
		if (pipes.length > 0) {
			streams.push(new Transform({
				transform: async (chunk, encoding, callback) => {
					try {
						let data = chunk.toString('utf8');
						for (const pipe of pipes) {
							data = await this.#runPipe(pipe, data, req, res);
						}
						callback(null, data);
					} catch (err) {
						callback(err)
					}
				}
			}));
		}

		if (streams.push(
			...this.#streams,
			...this.#streamFactories.map(f => f(req, res)).filter(s => s && typeof s.pipe === 'function')
		) === 0) return new PassThrough;

		const head = streams[0];
		let current = head;
		for (let i = 1; i < streams.length; i++) current = current.pipe(streams[i]);
		return head
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
		if (!(stream instanceof Transform)) throw new TypeError('stream must be an instance of: Transform')
		this.#streams.push(stream)
	}

	addStreamFactory(factory) {
		if (typeof factory !== 'function') throw new TypeError('Stream factory must be (req, res) => Transform');
		this.#streamFactories.push(factory)
	}
}