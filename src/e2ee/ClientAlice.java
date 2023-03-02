package e2ee;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.interfaces.DHPrivateKey;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class ClientAlice {
	
	private final static int KEY_SIZE = 512;
	
	private byte[] publicKeyAlice = null;
	private DHPrivateKey privateKeyAlice = null;
	
	private byte[] publicKeyBob = null;
	
	private Socket socket;
	private BufferedReader bufferedReader;
	private BufferedWriter bufferedWriter;
	private String username;
	
	private byte aesKey[] = new byte[32];
	
	/**
	 * This function aims at converting Byte Array to Hex String
	 * @param bytes (array to convert)
	 * @return Hex String of the bytes array
	 */
	private String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }
	
	/**
	 * This function aims at converting Hex String to Byte Array
	 * @param encoded (Hex String to convert)
	 * @return the byte array of Hex String
	 */
	private byte[] convertHexToBytes(String encoded) {
		
	    final byte result[] = new byte[encoded.length()/2];
	    final char enc[] = encoded.toCharArray();
	    for (int i = 0; i < enc.length; i += 2) {
	        StringBuilder curr = new StringBuilder(2);
	        curr.append(enc[i]).append(enc[i + 1]);
	        result[i/2] = (byte) Integer.parseInt(curr.toString(), 16);
	    }
	    return result;
	}
	
	/**
	 * Getter of AES key (= MessageKey in this class)
	 * @return AESKey
	 * @throws GeneralSecurityException 
	 * @throws IllegalStateException 
	 */
	private byte[] getAESKey() throws IllegalStateException, GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
	    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBob);
	    PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
	    
	    KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
	    keyAgree.init(this.privateKeyAlice);
	    keyAgree.doPhase(pubKey, true);

	    byte[] kg = keyAgree.generateSecret();
	    
	    this.aesKey = Arrays.copyOfRange(kg, 0, 32);

		return this.aesKey;
	}
	
	/**
	 * Getter of IV (fixed in this class)
	 * @return IV
	 */
	private byte[] getIV() {
		return "aaaaaaaaaaaaaaaa".getBytes();
	}
	
	/**
	 * This function is to calculate the hash value with specific algorithm
	 * <p>Ref: https://www.javacodemonk.com/create-hmacsha256-signature-in-java-3421c36d
	 * @param algorithm : hash algorithm
	 * @param key : the key for hash
	 * @param message : the message to hash (count in this class)
	 * @return the hash value of the message
	 */
	byte[] hmac(String algorithm, byte[] key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(message);
    }
	
	/**
	 * This function is to encrypt the plain text using AES/CEC/PKCS5PADDING
	 * @param plaintext : text to encrypt
	 * @return cipher text from plain text
	 * @throws GeneralSecurityException 
	 * @throws IllegalStateException 
	 */
	public String getCipherText(String plaintext) throws IllegalStateException, GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		
		SecretKey aesKey = new SecretKeySpec(this.getAESKey(), "AES");
		
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(this.getIV()));
		
		byte[] result = cipher.doFinal(plaintext.getBytes());
		
		return this.convertBytesToHex(result);
	}
	/**
	 * This function is to decrypt the cipher text using AES/CEC/PKCS5PADDING
	 * @param ciphertext : text to decrypt
	 * @return plain text from cipher text
	 * @throws GeneralSecurityException 
	 * @throws IllegalStateException 
	 */
	public String getPlainText(String ciphertext) throws IllegalStateException, GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		
		byte cipherBytes[] = convertHexToBytes(ciphertext);
		
		
		byte cipherTextBytes[] = cipherBytes;
		byte aeskeyBytes[] = this.getAESKey();
		
		SecretKey aesKey = new SecretKeySpec(aeskeyBytes, "AES");
		
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(this.getIV()));
		
		byte[] result = cipher.doFinal(cipherTextBytes);
		
		return new String(result, StandardCharsets.UTF_8);
	}
	/**
	 * This method is used to generate a key pair for Diffie-Hellman
	 */
	public void generateDHKeyPairs() {
		try { 
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
	        keyPairGen.initialize(ClientAlice.KEY_SIZE);
	        KeyPair kp = keyPairGen.generateKeyPair();
	        this.privateKeyAlice = (DHPrivateKey) kp.getPrivate();
	        this.publicKeyAlice = kp.getPublic().getEncoded();
	        
	    } catch (NoSuchAlgorithmException e) {
	       e.printStackTrace();
	    }
		System.out.println(">>> Generate public key: "+convertBytesToHex(this.publicKeyAlice));
		System.out.println(">>> Generate private key: "+convertBytesToHex(this.privateKeyAlice.getEncoded()));
		System.out.println();
	}
	
	public ClientAlice(Socket socket,String username) {
		try {
			this.socket = socket;
			this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			this.username = username;
			
			generateDHKeyPairs();
			System.out.println("*Use the command 'send' to send the public key");
			System.out.println();
			
		}catch(IOException e) {
			closeEverything(socket,bufferedReader,bufferedWriter);
		}
	}
	
	public void sendMessage() throws IllegalStateException, GeneralSecurityException {
		try {

			bufferedWriter.write(username);
			bufferedWriter.newLine();
			bufferedWriter.flush();
			Scanner scanner = new Scanner(System.in);
			while (socket.isConnected()) {
				String messageToSend = scanner.nextLine();
				if (messageToSend.equals("send")) {
					messageToSend = "Key:"+convertBytesToHex(publicKeyAlice);
				}else {
					messageToSend = username + ": "+messageToSend;
					messageToSend = getCipherText(messageToSend);
					System.out.println(">>> This AES Key: "+convertBytesToHex(aesKey));
				}
				bufferedWriter.write(messageToSend);
				System.out.println();
				bufferedWriter.newLine();
				bufferedWriter.flush();
			}
		}catch(IOException e) {
			closeEverything(socket,bufferedReader,bufferedWriter);
		}
	}
	
	public void listenMessage() {
		new Thread(new Runnable() {
			public void run() {
				String msgFromGroupChat;
				
				while (socket.isConnected()) {
					try {
						msgFromGroupChat = bufferedReader.readLine();
						if (msgFromGroupChat.contains("Server: ")) {
							System.out.println(msgFromGroupChat);
							System.out.println();
						}else if (msgFromGroupChat.contains("Key:")) {
							publicKeyBob = convertHexToBytes(msgFromGroupChat.substring(4));
							System.out.println(">>> Public Key of Bob received: "+ msgFromGroupChat.substring(4));
							System.out.println();
						}else {
							System.out.println(">>> Code received: "+msgFromGroupChat);
							String realMessage = getPlainText(msgFromGroupChat);
							System.out.println(realMessage);
							System.out.println();
						}
					}catch(IOException e) {
						closeEverything(socket,bufferedReader,bufferedWriter);
					} catch (InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidAlgorithmParameterException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalBlockSizeException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (BadPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalStateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidKeySpecException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (GeneralSecurityException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}).start();
	}
	
	public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
		// TODO Auto-generated method stub
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

	public static void main(String[] args) throws UnknownHostException, IOException, IllegalStateException, GeneralSecurityException {

		Scanner scanner = new Scanner(System.in);
		System.out.println("Enter your username for the group chat: ");
		String username = scanner.nextLine();

		Socket socket = new Socket("localhost",1234);
		ClientAlice client = new ClientAlice(socket,username);
		client.listenMessage();
		client.sendMessage();
	}
}
