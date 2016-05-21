package practiceRSA;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

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
		n = p.multiply(q);
		v = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		e = BigInteger.probablePrime(bitLength/2, rng);
		
		while(v.gcd(e).compareTo(BigInteger.ONE)>0 && e.compareTo(v)<0){
			e.add(BigInteger.ONE);
		}		
		d = e.modInverse(v);
	}
	
	public static void main(String[] args) throws IOException {
		RSA_Algorithm rsa = new RSA_Algorithm();
	}
}
