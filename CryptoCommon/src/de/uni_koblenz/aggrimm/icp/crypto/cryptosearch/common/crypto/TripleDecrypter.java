package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;

public class TripleDecrypter extends CryptoBase {

	public TripleDecrypter(byte[] iv) throws CryptoException {
		super(iv);
	}

	public String[] decryptWithDecryptionKey(BigInteger n, byte[] data,
			byte[] decryptionKey) throws Exception {

		this.cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptionKey,
				0, Constants.SECRET_KEY_SPEC_LENGTH, Constants.KEY_ALGORITHM),
				new IvParameterSpec(this.iv));

		// Only continue if the encrypted data has the correct block size.
		if (data.length % Constants.BLOCK_SIZE != 0) {
			System.out.println("WRONG BLOCK SIZE");
			return null;
		}

		// Extract the first BLOCK_SIZE bytes. These bytes may contain the
		// marker bytes.
		byte[] marker = this.cipher.update(data, 0, Constants.BLOCK_SIZE);

		// Check if the first 16 bytes are really the marker bytes. If not,
		// return null indicating a wrong decryption.
		for (int i = 0; i < Constants.BLOCK_SIZE; ++i) {
			if (marker[i] != Constants.TRIPLE_MARKER[i]) {
				// System.out.println("WRONG MARKER");
				return null;
			}
		}

		// Encrypt the rest of the data excluding the marker bytes.
		byte[] result = this.cipher.doFinal(data, Constants.BLOCK_SIZE,
				data.length - Constants.BLOCK_SIZE);

		String[] res = new String[3];
		int resPos = 0;
		int lastPos = 0;

		// Split the resulting byte array into separate byte arrays.
		for (int i = 0; i < result.length; ++i) {
			if (result[i] == Constants.SEPARATOR[0]) {
				res[resPos++] = new String(Arrays.copyOfRange(result, lastPos,
						i), Constants.STRING_CHARSET);
				lastPos = i + 1;
				continue;
			}
			else if (result[i] == Constants.PADDING[0])
				break;
		}

		return res;
	}

	public String[] decryptWithPatternKey(BigInteger n, byte[] data,
			byte[] patternKey) throws Exception {

		byte[] decryptionKey = this.digester.digest(this.combFunc.combineNone(
				n, patternKey));

		this.cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptionKey,
				0, Constants.SECRET_KEY_SPEC_LENGTH, Constants.KEY_ALGORITHM),
				new IvParameterSpec(this.iv));

		// Only continue if the encrypted data has the correct block size.
		if (data.length % Constants.BLOCK_SIZE != 0) {
			System.out.println("WRONG BLOCK SIZE");
			return null;
		}

		// Extract the first BLOCK_SIZE bytes. These bytes may contain the
		// marker bytes.
		byte[] marker = this.cipher.update(data, 0, Constants.BLOCK_SIZE);

		// Check if the first 16 bytes are really the marker bytes. If not,
		// return null indicating a wrong decryption.
		for (int i = 0; i < Constants.BLOCK_SIZE; ++i) {
			if (marker[i] != Constants.TRIPLE_MARKER[i]) {
				// System.out.println("WRONG MARKER");
				return null;
			}
		}

		// Encrypt the rest of the data excluding the marker bytes.
		byte[] result = this.cipher.doFinal(data, Constants.BLOCK_SIZE,
				data.length - Constants.BLOCK_SIZE);

		String[] res = new String[3];
		int resPos = 0;
		int lastPos = 0;

		// Split the resulting byte array into separate byte arrays.
		for (int i = 0; i < result.length; ++i) {
			if (result[i] == Constants.SEPARATOR[0]) {
				res[resPos++] = new String(Arrays.copyOfRange(result, lastPos,
						i), Constants.STRING_CHARSET);
				lastPos = i + 1;
				continue;
			}
			else if (result[i] == Constants.PADDING[0])
				break;
		}

		return res;
	}

	// public String[] decrypt(byte[] data, byte[] queryKey) throws Exception {
	// return decryptValues(data,
	// this.digester.digest(this.utils.combineNone(queryKey)));
	// }

	// public String[] decrypt(byte[] data, byte[] queryKey, byte[]
	// queryParameter1)
	// throws Exception {
	// byte[] decryptionKey =
	// this.digester.digest(this.utils.combineValues(queryKey,
	// queryParameter1));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decrypt(byte[] data, byte[] queryKey,
	// byte[] queryParameter1, byte[] queryParameter2) throws Exception {
	// byte[] decryptionKey =
	// this.digester.digest(this.utils.combineValues(queryKey,
	// queryParameter1, queryParameter2));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decrypt(byte[] data, byte[] queryKey,
	// byte[] queryParameter1, byte[] queryParameter2,
	// byte[] queryParameter3) throws Exception {
	// byte[] decryptionKey =
	// this.digester.digest(this.utils.combineValues(queryKey,
	// queryParameter1, queryParameter2, queryParameter3));
	// return decryptValues(data, decryptionKey);
	// }

	// public String[] decryptMMM(byte[] basicKey, byte[] data) throws Exception
	// {
	// return decryptValues(data, basicKey);
	// }
	//
	// public String[] decryptMMP(byte[] basicKey, byte[] data, byte[] object)
	// throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(object));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptPMM(byte[] basicKey, byte[] data, byte[] subject)
	// throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(subject));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptMPM(byte[] basicKey, byte[] data, byte[]
	// predicate)
	// throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(predicate));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptPPM(byte[] basicKey, byte[] data, byte[] subject,
	// byte[] predicate) throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(subject), this.digester.digest(predicate));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptPMP(byte[] basicKey, byte[] data, byte[] subject,
	// byte[] object) throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(subject), this.digester.digest(object));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptMPP(byte[] basicKey, byte[] data, byte[]
	// predicate,
	// byte[] object) throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(predicate), this.digester.digest(object));
	// return decryptValues(data, decryptionKey);
	// }
	//
	// public String[] decryptPPP(byte[] basicKey, byte[] data, byte[] subject,
	// byte[] predicate, byte[] object) throws Exception {
	// byte[] decryptionKey = this.utils.combineValues(basicKey,
	// this.digester.digest(subject), this.digester.digest(predicate),
	// this.digester.digest(object));
	// return decryptValues(data, decryptionKey);
	// }

}
