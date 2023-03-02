package whatsApp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	private ServerSocket serverSocket;

	public Server(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	public String startServer() {
		String response = "";
		try {
			
			while(!serverSocket.isClosed()) {
				
				Socket socket = serverSocket.accept();
				response = "A new client has connected";
				ClientHandler clientHandler = new ClientHandler(socket);
			
				Thread thread = new Thread(clientHandler);
				thread.start();
				
			}
		}catch(IOException e) {
				e.printStackTrace();
		}
		return response;
	}
	
	public void closeServerSocket() {
		try {
			if (serverSocket != null) {
				serverSocket.close();
			}
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws IOException {
		
		ServerSocket serverSocket = new ServerSocket(1234);
		Server server = new Server(serverSocket);
		server.startServer();
	}
}
