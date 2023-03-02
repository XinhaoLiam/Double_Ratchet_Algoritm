package whatsApp;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the HKDF using HMAC-SHA256.
 * <p>Ref: https://www.huangchaoyu.com/2019/11/28/java-hkdf�㷨������Կ/
 * @author Liamxh
 *
 */
public class KDF {
	private static byte[] hkdfExtract(byte[] salt, byte[] passsword) throws NoSuchAlgorithmException, InvalidKeyException {
		//��ȡ��ϢժҪ�㷨��hdkfSha1 ����sha1�㷨��hdkfSha256����sha256�㷨��Ҳ����hkdf�㷨���ĳһ����ϢժҪ�㷨ʹ��
		Mac mac = Mac.getInstance("HmacSHA256");
		//��salt��Ϊ��Կ��ʼ��
		SecretKeySpec keySpec = new SecretKeySpec(salt, "HmacSHA256");
		mac.init(keySpec);
		//��password����ժҪ
		return mac.doFinal(passsword);
	}
	private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(prk, "HmacSHA256");
        mac.init(keySpec);
        byte[] result = new byte[length];
        int pos = 0;
        byte[] digest = new byte[0];
        byte t = 1;
        while (pos < result.length) {
            mac.update(digest);
            mac.update(info);
            mac.update(t);
            digest = mac.doFinal();
            System.arraycopy(digest, 0, result, pos, Math.min(digest.length, length - pos));
            pos += digest.length;
            t++;
        }
        return result;
    }
	public final static byte[] createHkdfKey(byte[] password,String info, byte[] salt, int keySize) throws GeneralSecurityException {
		//��һ�� ����ȡ���õ�prk    
		byte[] prk = hkdfExtract(salt, password);
		//�ڶ�������չ    
		return hkdfExpand(prk, info.getBytes(), keySize);
	}

}