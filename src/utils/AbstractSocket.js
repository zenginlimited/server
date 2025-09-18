export default class AbstractSocket {
	constructor(sock) {
		Object.defineProperties(this, {
			_socket: { value: sock }
		});
	}
}