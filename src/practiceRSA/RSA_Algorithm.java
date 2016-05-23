package practiceRSA;

import java.math.BigInteger;
import java.util.Random;
import java.io.*;

public class RSA_Algorithm {
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger v;
	private BigInteger e;
	private BigInteger d;
	private int bitLength = 1024;
	private Random rng;
	
	public RSA_Algorithm(){
		rng = new Random();
		p = BigInteger.probablePrime(bitLength/2, rng);
		q = BigInteger.probablePrime(bitLength/2, rng);
		// n=p*q
		n = p.multiply(q);
		// v=(p-1)*(q-1)
		v = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.probablePrime(bitLength/2, rng);
		
		// gcd(v,e)=1 && e<v
		while(v.gcd(e).compareTo(BigInteger.ONE)>0 && e.compareTo(v)<0){
			e.add(BigInteger.ONE);
		}		
		d = e.modInverse(v);
	}
	
	public static void main(String[] args) throws IOException {
		RSA_Algorithm rsa = new RSA_Algorithm();
		DataInputStream in = new DataInputStream(System.in);
		String plaintext;
		System.out.println("Public Key : (" + rsa.e + "," + rsa.n + ")");
		System.out.println("Private Key : (" + rsa.d + "," + rsa.n + ")");

		System.out.println("Enter the plain text:");
		plaintext=in.readLine();
		System.out.println("Encrypting String: " + plaintext);
		System.out.println("String in Bytes: " + bytesToString(plaintext.getBytes()));
		
		//encrypt
		byte[] encrypted = rsa.encrypt(plaintext.getBytes());
		System.out.println("Encrypted String in Bytes: " + bytesToString(encrypted));
		
		//decrypt
		byte[] decrypted = rsa.decrypt(encrypted);
		System.out.println("Decrypted String in Bytes: " + bytesToString(decrypted));		
		System.out.println("Decrypted String: " + new String(decrypted));

	}
	
	private static String bytesToString(byte[] encrypted){
		String test = "";
		for(byte b : encrypted){
			test += Byte.toString(b);
		}		
		return test;
	}
	
	//Encrypt message
	public byte[] encrypt(byte[] message){
		return (new BigInteger(message)).modPow(e, n).toByteArray();
	}
	
	//Decrypt message
	public byte[] decrypt(byte[] message){
		return (new BigInteger(message)).modPow(d, n).toByteArray();
	}
}

