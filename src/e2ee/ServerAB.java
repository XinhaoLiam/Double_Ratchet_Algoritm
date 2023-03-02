package e2ee;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerAB {
	private ServerSocket serverSocket;

	public ServerAB(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	public String startServer() {
		String response = "";
		try {
			
			while(!serverSocket.isClosed()) {
				
				Socket socket = serverSocket.accept();
				response = "A new client has connected";
				ClientHandlerAlice clientHandlerAlice = new ClientHandlerAlice(socket);
			
				Thread thread = new Thread(clientHandlerAlice);
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
		ServerAB serverAB = new ServerAB(serverSocket);
		serverAB.startServer();
	}
}
