package com.android.insecurebankv2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/*
The page that holds the logic for encryption and decryption used in the application
@author Dinesh Shetty
*/
public class CryptoClass {

	String plainText;
	byte[] cipherData;
	String base64Text;
	String cipherText;

	/*
	 * The function that handles the aes256 encryption.
	 * ivBytes: Initialization vector used by the encryption function
	 * keyBytes: Key used as input by the encryption function
	 * textBytes: Plaintext input to the encryption function
	 */
	public static byte[] aes256encrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes)
			throws UnsupportedEncodingException,
			NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			IllegalBlockSizeException,
			BadPaddingException {

		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = null;
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(textBytes);
	}

	/*
	 * The function that handles the aes256 decryption.
	 * ivBytes: Initialization vector used by the decryption function
	 * keyBytes: Key used as input by the decryption function
	 * textBytes: Ciphertext input to the decryption function
	 */
	public static byte[] aes256decrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes)
			throws UnsupportedEncodingException,
			NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			IllegalBlockSizeException,
			BadPaddingException {

		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(textBytes);

	}

	/*
	 * The function that uses the aes256 decryption function
	 * theString: Ciphertext input to the decryption function
	 * plainText: Plaintext output of the encryption operation
	 */
	public String aesDeccryptedString(String theString)
			throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		byte[] keyBytes = key.getBytes("UTF-8");
		cipherData = CryptoClass.aes256decrypt(ivBytes, keyBytes,
				Base64.decode(theString.getBytes("UTF-8"), Base64.DEFAULT));
		plainText = new String(cipherData, "UTF-8");
		return plainText;
	}

	/*
	 * The function that uses the aes256 encryption function
	 * theString: Plaintext input to the encryption function
	 * cipherText: Ciphertext output of the encryption operation
	 */
	public String aesEncrypt(String plainText, String key, String iv)
			throws Exception {
		byte[] keyBytes = key.getBytes("UTF-8");
		byte[] ivBytes = iv.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(ivBytes));
		byte[] cipherData = cipher.doFinal(plainText.getBytes());
		String cipherText = Base64.encodeToString(cipherData);
		return cipherText;
	}
}