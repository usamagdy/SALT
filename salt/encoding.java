package salt;
	import java.nio.charset.StandardCharsets;
	import java.security.SecureRandom;
	import java.security.spec.KeySpec;

	import javax.crypto.Cipher;
	import javax.crypto.SecretKey;
	import javax.crypto.SecretKeyFactory;
	import javax.crypto.spec.IvParameterSpec;
	import javax.crypto.spec.PBEKeySpec;
	import javax.crypto.spec.SecretKeySpec;

	import org.apache.commons.codec.DecoderException;
	import org.apache.commons.codec.binary.Base64;
	import org.apache.commons.codec.binary.Hex;

	public class encoding  
	{  
		private static final int keySize = 128;
	    private static final int iterationCount = 1000;
	    private final Cipher cipher;
	    
	    public encoding() {
	        try {
	            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        }
	        catch (Exception e) {
	            throw fail(e);
	        }
	    }
	
	    
	    public String encrypt(String salt, String iv, String passphrase, String plaintext) {
	        SecretKey key = generateKey(salt, passphrase);
	        byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes(StandardCharsets.UTF_8));
	        return base64(encrypted);
	    }
	    
	    
	    public String decode(String salt, String iv, String passphrase, String ciphertext) {
	        SecretKey key = generateKey(salt, passphrase);
	        byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, base64(ciphertext));
	        return new String(decrypted, StandardCharsets.UTF_8);
	    }
	    
	    private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
	        try {
	            cipher.init(encryptMode, key, new IvParameterSpec(hex(iv)));
	            return cipher.doFinal(bytes);
	        }
	        catch (Exception e) {
	            throw fail(e);
	        }
	    }
	    
	    private SecretKey generateKey(String salt, String passphrase) {
	        try {
	            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
	            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	            return key;
	        }
	        catch (Exception e) {
	            throw fail(e);
	        }
	    }
	    
	    public static String random(int length) {
	        byte[] salt = new byte[length];
	        new SecureRandom().nextBytes(salt);
	        return hex(salt);
	    }
	     
	    public static String base64(byte[] bytes) {
	        return Base64.encodeBase64String(bytes);
	    }
	    
	    public static byte[] base64(String str) {
	        return Base64.decodeBase64(str);
	    }
	    
	    public static String hex(byte[] bytes) {
	        return Hex.encodeHexString(bytes);
	    }
	    
	    public static byte[] hex(String str) {
	        try {
	            return Hex.decodeHex(str.toCharArray());
	        }
	        catch (DecoderException e) {
	            throw new IllegalStateException(e);
	        }
	    }
	    
	    private IllegalStateException fail(Exception e) {
	        return new IllegalStateException(e);
	    }
		

	    
	    public static void main(String args[]) throws Exception {
	        
			encoding encode = new encoding();
			String salt =random(3);
			System.out.println("Salt    " + salt);
			
			String iv="678d13875330e1c2902661fe4f38d898";
			String passphrase="hSywUTurmQKBKHT";
			String ciphertext =encode.encrypt(salt, iv, passphrase, "sayed@say999889w9r8we9rew89r8wed");
			
			System.out.println("encrypted --> "+ciphertext);
			
			
			System.out.println("Decrypted" + encode.decrypt(salt, iv, passphrase, ciphertext));
			
			
	    }
	    
	    public static  String decrypt(String salt ,String iv , String passphrase , String ciphertext)
	    {
	    	return new encoding().decode(salt, iv, passphrase, ciphertext);
	    	
	    }
	}  




