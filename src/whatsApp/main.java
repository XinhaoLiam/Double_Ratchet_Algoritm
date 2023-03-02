package whatsApp;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class main {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		String plaintext = "hello";
		String message = "250372aaa9925180fb711e2ab9537bc2f32dad53ccf9e030a84fb1b3f325cbe2";
		String key = "e289d8b9daaabe1cacf47eccc9c81d7d";
		
		String str = plaintext+"|"+key;
		
		String[] temp = str.split("\\|");
		System.out.println(temp[0]);
	}

}
