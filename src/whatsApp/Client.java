package whatsApp;

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
import javax.crypto.interfaces.DHPublicKey;

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

import java.security.SecureRandom;
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

public class Client {
	
	private final static int KEY_SIZE = 512;
	
	private Socket socket;
	private BufferedReader bufferedReader;
	private BufferedWriter bufferedWriter;
	private String username;
	
	private byte rootKey[] = convertHexToBytes("c88203b1c31fea03382f4f166894eef8c9f764766e4fbf287de3e104b6a0163f");
	private byte chainKey[] = convertHexToBytes("fa02fe925a1658a8ae43d0b9dcbc1c3a8c0e2838095defe1bb2b280ce4cded06");
	private byte messageKey[] = new byte[32];
	private DHPrivateKey privateKey = null;
	private byte ephemeralpubKey[] = null;
	private int count = 1;
	
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
	 */
	private byte[] getAESKey() {
		return this.messageKey;
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
	 * This function is to calculate message key from the chain key using HMAC-SHA256
	 * <p>Ref: https://www.javacodemonk.com/create-hmacsha256-signature-in-java-3421c36d
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	private void MsgKeyFromChainKey() throws InvalidKeyException, NoSuchAlgorithmException {
		System.out.println("------ Forward Ratchet for Chain Key ------");
		this.messageKey = hmac("HmacSHA256", this.chainKey, Integer.toHexString(this.count).getBytes());
		System.out.println(">>> This Msg Key: "+convertBytesToHex(this.messageKey));
		this.count += 1;
		this.chainKey = hmac("HmacSHA256", this.chainKey, Integer.toHexString(this.count).getBytes());
		System.out.println(">>> Next Chain Key: "+convertBytesToHex(this.chainKey));
		System.out.println("-------------------------------------------");
	}
	/**
	 * This fucntion is to calculate an (DH) ephemeral key to transfer with the message
	 * <p>Ref: https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-key-pair-for-diffie-hellman-algorithm
	 * @throws NoSuchAlgorithmException
	 */
	private String getEphemeralKey() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		kpg.initialize(KEY_SIZE);
		KeyPair kp = kpg.generateKeyPair();
		DHPublicKey pk = (DHPublicKey) kp.getPublic();
		this.privateKey = (DHPrivateKey) kp.getPrivate();
		String pkString = convertBytesToHex(pk.getEncoded());
		return pkString;
	}
	
	/**
	 * This function is to generate a new ChainKey and new RootKey when the private key is not null using DH.
	 * <p>Ref: https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
	 * @param ephemeralSender: the public key of the sender
	 * @throws IllegalStateException 
	 * @throws GeneralSecurityException 
	 */
	private final void newChainKeyRootKey() throws IllegalStateException, GeneralSecurityException {
		
		if (this.ephemeralpubKey == null || this.privateKey == null) {
			return;
		}
		
		System.out.println("----- Start Double Ratchet Alogorithm -----");
		System.out.println(">>>>> Diffie-Hellman Ratchet");
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
	    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(this.ephemeralpubKey);
	    PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
	    
	    KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
	    keyAgree.init(this.privateKey);
	    keyAgree.doPhase(pubKey, true);
	    
	    byte[] secret = keyAgree.generateSecret();
	    System.out.println("Result: " + convertBytesToHex(secret));
	    System.out.println(">>>>> KDF Ratchet");
	    
	    byte newKey[] = KDF.createHkdfKey(this.rootKey,"",secret,64);

		this.chainKey = Arrays.copyOfRange(newKey,0, 32);
		this.rootKey = Arrays.copyOfRange(newKey,32, 64);
		
		System.out.println("New Root Key: "+convertBytesToHex(rootKey));
		System.out.println("New Chain Key: "+convertBytesToHex(chainKey));
		
		System.out.println("-------------------------------------------");
		System.out.println();
		
		this.ephemeralpubKey = null;
		this.privateKey = null;
		this.count = 1;
	}
	/**
	 * This function is to encrypt the plain text using AES/CEC/PKCS5PADDING
	 * @param plaintext : text to encrypt
	 * @return cipher text from plain text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String getCipherText(String plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
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
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String getPlainText(String ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");		
		
		byte cipherTextBytes[] = convertHexToBytes(ciphertext);
		byte aeskeyBytes[] = this.getAESKey();
		
		SecretKey aesKey = new SecretKeySpec(aeskeyBytes, "AES");
		
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(this.getIV()));
		
		byte[] result = cipher.doFinal(cipherTextBytes);
		
		return new String(result, StandardCharsets.UTF_8);
	}
	
	public Client(Socket socket,String username) {
		try {
			this.socket = socket;
			this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			this.username = username;

			System.out.println(">>> First Root key: "+convertBytesToHex(this.rootKey));
			System.out.println(">>> First Chain key: "+convertBytesToHex(this.chainKey));
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
				String ephemeralKey = getEphemeralKey();
				newChainKeyRootKey();
				MsgKeyFromChainKey();
				System.out.println();
				String codeToSend = getCipherText(username + ": "+messageToSend);
				bufferedWriter.write(codeToSend+"|"+ephemeralKey);
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
						}else {
							System.out.println(">>> Code received: "+msgFromGroupChat);
							String[] temp = msgFromGroupChat.split("\\|");
							ephemeralpubKey = convertHexToBytes(temp[1]);
							newChainKeyRootKey();
							MsgKeyFromChainKey();
							String realMessage = getPlainText(temp[0]);
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
		Client client = new Client(socket,username);
		client.listenMessage();
		client.sendMessage();
	}
}
