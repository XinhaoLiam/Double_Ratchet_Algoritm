package e2ee;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.ArrayList;

public class ClientHandlerAlice implements Runnable{

	public static ArrayList<ClientHandlerAlice> clientHandlerAlices = new ArrayList<>();
	private Socket socket;
	private BufferedReader bufferedReader;
	private BufferedWriter bufferedWriter;
	private String username;
	private String publicKey;
	
	public ClientHandlerAlice(Socket socket) {
		try {
			this.socket = socket;
			this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			this.username = bufferedReader.readLine();
			clientHandlerAlices.add(this);
			broadcastMessage("Server: "+ username + " has entered the chat!");
		}catch (IOException e) {
			closeEverything(socket,bufferedReader,bufferedWriter);
		}
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		String messageFromClient;
		
		while (socket.isConnected()) {
			try {
				messageFromClient = bufferedReader.readLine();
				broadcastMessage(messageFromClient);
			}catch(IOException e) {
				closeEverything(socket,bufferedReader,bufferedWriter);
				break;
			}
		}
	}

	public void broadcastMessage(String messageToSend) {
		for (ClientHandlerAlice clientHandlerAlice : clientHandlerAlices) {
			try {
				if (!clientHandlerAlice.username.equals(username)) {
					clientHandlerAlice.bufferedWriter.write(messageToSend);
					clientHandlerAlice.bufferedWriter.newLine();
					clientHandlerAlice.bufferedWriter.flush();
				}
			}catch(IOException e) {
				closeEverything(socket,bufferedReader,bufferedWriter);
			}
		}
	}
	
	public void removeClientHandler() {
		clientHandlerAlices.remove(this);
		//broadcastMessage("Server: "+ key +" has left the chat!");
	}
	
	public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
		// TODO Auto-generated method stub
		removeClientHandler();
		try {
			if (bufferedReader!=null) {
				bufferedReader.close();
			}
			if (bufferedWriter!=null) {
				bufferedWriter.close();
			}
			if (socket!=null) {
				socket.close();
			}
		}catch(IOException e) {
			e.printStackTrace();
		}
		
	}

}
