package practiceRSA;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class OAEP {
	static int hLen = 32;
	public static final SecureRandom random = new SecureRandom();
	private static String LHash = "RSA-OAEP";
	
	public static byte[] SHA256(byte[] m) throws NoSuchAlgorithmException{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(m);
	}	
	
	public static byte[] MGF(byte[] seed, int seedOffset, int seedLength, int desiredLength) throws NoSuchAlgorithmException{
		int hLen = 32;
		int offset = 0;
		int i = 0;
		byte[] mask = new byte[desiredLength];
		byte[] temp = new byte[seedLength + 4];
		System.arraycopy(seed, seedOffset, temp, 4, seedLength);
		while(offset < desiredLength){
			temp[0] = (byte)(i>>>24);
			temp[1] = (byte)(i>>>16);
			temp[2] = (byte)(i>>>8);
			temp[3] = (byte)i;
			int remaining = desiredLength - offset;
			System.arraycopy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
			offset = offset + hLen;
			i = i + 1;
		}
		return mask;
	}
	
	public static byte[] unPad(byte[] message, String label) throws Exception {
		if(!label.equals(LHash)){
			return null;
		}
		
		int mLen = message.length;
		int hLen = 32;
		if(mLen < (hLen << 1) + 1){
			return null;
		}
		byte[] copy = new byte[mLen];
		System.arraycopy(message, 0, copy, 0, mLen);
		byte[] seedMask = MGF(copy, hLen, mLen - hLen, hLen);
		for (int i = 0; i < hLen; i++){
			copy[i] ^= seedMask[i];
		}
		byte[] hash = SHA256(label.getBytes("UTF-8"));
		byte[] dataBlockMask = MGF(copy, 0, hLen, mLen - hLen);
		int index = -1;
		for(int i = hLen; i < mLen; i++){
			copy[i] ^= dataBlockMask[i - hLen];
			if(i < (hLen << 1)){
				if(copy[i] != hash[i - hLen]){
					return null;
				}
			}else if(index == -1){
				if(copy[i] == 1){
					index = i + 1;
				}
			}
		}
		if(index == -1 || index == mLen){
			return null;
		}
		byte[] unpadded = new byte[mLen - index];
		System.arraycopy(copy, index, unpadded, 0, mLen - index);
		return unpadded;
	}
	
	// mLen <= length - hLen * 2 - 1
	public static byte[] pad(byte[] message, int length , String label) throws Exception{
		if(!label.equals(LHash)){
			return null;
		}
		int mLen = message.length;
		int hLen = 32;
		if(mLen > length - (hLen << 1) - 1){
			return null;
		}
		int zeroPad = length - mLen - (hLen << 1) - 1;
		byte[] dataBlock = new byte[length - hLen];
		System.arraycopy(SHA256(label.getBytes("UTF-8")), 0, dataBlock, 0, hLen);
		System.arraycopy(message, 0, dataBlock, hLen + zeroPad + 1, mLen);
		dataBlock[hLen + zeroPad] = 1;
		
		byte[] seed = new byte[hLen];
		random.nextBytes(seed);
		
		byte[] dataBlockMask = MGF(seed, 0, hLen, length - hLen);
		xorBlock(dataBlock, dataBlockMask, dataBlock);
		
		byte[] seedMask = MGF(dataBlock, 0, length - hLen, hLen);
		xorBlock(seed, seedMask, seed);
		
		byte[] padded = new byte[length];
		System.arraycopy(seed, 0, padded, 0, hLen);
		System.arraycopy(dataBlock, 0, padded, hLen, length - hLen);		
		return padded;
	}

	private static void xorBlock(byte[] a, byte[] b, byte[] dst) {
		for(int i = 0; i < a.length; ++i){
			dst[i] = (byte)(a[i]^b[i]);
		}
	}
	
	public static byte[] encrypt(byte[] message, RSA rsa, int length, String label) throws Exception{
		int mLen = message.length;
		if(mLen > length - (hLen << 1) - 1){
			System.out.println("Encoding error: message too long. Try again.");
			return null;
		}
		byte[] out = new byte[length];
		out = pad(message, length, label);
		
		BigInteger m = new BigInteger(out);
		BigInteger c = rsa.encrypt(m);
		
		return c.toByteArray();
	}
	
	public static byte[] decrypt(byte[] cipherText, RSA rsa, String label) throws Exception{
		int mLen = cipherText.length;
		if(mLen < (hLen << 1) + 1){
			System.out.println("Decoding error.");
			return null;
		}
		
		if(mLen != (rsa.n.bitLength() / 8)){
			System.out.println("Decoding error." + " " + (rsa.n.bitLength() / 8) + " " + mLen);
		}
		
		BigInteger c = new BigInteger(cipherText);
		BigInteger m = rsa.decrypt(c);
		byte[] out = unPad(m.toByteArray(), label);
		return out;
	}

}
