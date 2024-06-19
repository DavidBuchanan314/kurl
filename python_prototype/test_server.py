import socket
import ssl

HOST = "127.0.0.1"
PORT = 1337

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("./cert.pem", "./key.pem")
ctx.keylog_filename = "/dev/stderr"

server = ctx.wrap_socket(server, server_side=True)

if __name__ == "__main__":
	server.bind((HOST, PORT))
	server.listen(0)

	while True:
		connection, client_address = server.accept()
		data = connection.recv(1024)
		print(f"Received: {data}")
		connection.sendall(b"echo " + data)
		connection.close()
