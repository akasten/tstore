package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;

public class CryptoUtils {

	private CryptoUtils() {
	}

	public static byte[][] createBasicKeys() throws CryptoException {
		try {
			KeyGenerator keyGenerator = javax.crypto.KeyGenerator
					.getInstance(Constants.KEY_ALGORITHM);
			keyGenerator.init(Constants.AES_KEY_LENGTH);

			return new byte[][] { keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded(),
					keyGenerator.generateKey().getEncoded() };
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}

	public static byte[] createIV() {
		SecureRandom rnd = new SecureRandom();
		byte[] iv = new byte[16];

		rnd.nextBytes(iv);
		return iv;
	}

	public static BigInteger createN() {
		SecureRandom rnd = new SecureRandom();

		BigInteger p = new BigInteger(Constants.RSA_KEY_LENGTH / 2,
				Constants.PRIME_CERTAINTY, rnd);
		BigInteger q = new BigInteger(Constants.RSA_KEY_LENGTH / 2,
				Constants.PRIME_CERTAINTY, rnd);

		return p.multiply(q);
	}
}
