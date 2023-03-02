package whatsApp;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the HKDF using HMAC-SHA256.
 * <p>Ref: https://www.huangchaoyu.com/2019/11/28/java-hkdf算法生成密钥/
 * @author Liamxh
 *
 */
public class KDF {
	private static byte[] hkdfExtract(byte[] salt, byte[] passsword) throws NoSuchAlgorithmException, InvalidKeyException {
		//获取消息摘要算法，hdkfSha1 就用sha1算法，hdkfSha256就用sha256算法，也就是hkdf算法配合某一个消息摘要算法使用
		Mac mac = Mac.getInstance("HmacSHA256");
		//用salt作为密钥初始化
		SecretKeySpec keySpec = new SecretKeySpec(salt, "HmacSHA256");
		mac.init(keySpec);
		//对password进行摘要
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
		//第一步 先提取，得到prk    
		byte[] prk = hkdfExtract(salt, password);
		//第二步，扩展    
		return hkdfExpand(prk, info.getBytes(), keySize);
	}

}