# @zenginlimited/server
A lightweight and customizable web-server tailored for Zengin services, supporting both HTTP and HTTPS.

## Features
- Minimal and easy-to-use API
- Supports both HTTP and HTTPS
- Fully modular and ES Module ready
- TypeScript type definitions included
- Tailored for [Zengin](https://github.io/zenginlimited) services

## Installation
```cmd
npm install @zenginlimited/server
```

## Usage
```js
import { WebServer } from "@zenginlimited/server";

const server = new WebServer({ port: 80 });

server.listen();
```
**Example with HTTPS:**
```js
import { readFileSync } from "fs";
import { WebServer } from "@zenginlimited/server";

const server = new WebServer({
	port: 443,
	ssl: {
		key: readFileSync("./ssl/key.pem"),
		cert: readFileSync("./ssl/cert.pem")
	}
});

server.listen();
```

## License
GNU General Public License v2.0. See [LICENCE](https://github.com/zenginlimited/server/LICENSE) for details.