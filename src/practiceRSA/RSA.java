package practiceRSA;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class RSA {
	BigInteger p;
	BigInteger q;
	BigInteger n;
	BigInteger v;
	BigInteger e;
	BigInteger d;
	int bitLength = 2048;
	Random rng;

	
	public void genrKeys(){
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
	
	//Encrypt message
	public String encrypt(String message){
		return (new BigInteger(message.getBytes())).modPow(e, n).toString();
	}
	
	//Decrypt message
	public String decrypt(String message){
		return new String((new BigInteger(message)).modPow(d, n).toByteArray());
	}
	
	public BigInteger encrypt(BigInteger message){
		return message.modPow(e, n);
	}
	
	public BigInteger decrypt(BigInteger message){
		return message.modPow(d, n);
	}
}
