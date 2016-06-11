package practiceRSA;

import java.io.DataInputStream;

public class Test {
	public static void main(String[] args) throws Exception{
		RSA rsa = new RSA();
		rsa.genrKeys();
		DataInputStream in = new DataInputStream(System.in);
		String plainText;

		System.out.println("Enter the plain text:");
		plainText=in.readLine();


		String encrypted = rsa.encrypt(plainText);
		System.out.println("Encrypted String: " + encrypted);
		
		String decrypted = rsa.decrypt(encrypted);
		System.out.println("Decrypted String: " + decrypted);		

		String label = "RSA-OAEP";
		
		byte[] m = OAEP.encrypt(plainText.getBytes("UTF-8"), rsa, plainText.length()+32+32+1, label);
		StringBuilder sb = new StringBuilder();
		//to Hex String
		for(byte b : m) {
			sb.append(String.format("%02X", b));			
		}
		System.out.println("Encrypted String using OAEP: " + sb.toString());
		System.out.println("Decrypted String using OAEP: " + new String(OAEP.decrypt(m, rsa, label)));
	}
}
