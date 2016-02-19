package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;

/**
 * This class is used for encrypting triples. An encrypted triple consists of
 * eight different ciphertexts, each ciphertext representing one particular
 * pattern type.
 * 
 * @author Andreas Kasten
 */
public class TripleEncrypter extends CryptoBase {

	public TripleEncrypter(byte[] iv) throws CryptoException {
		super(iv);
	}

	// TRIPLE_MARKER <sbj> SEPARATOR <prd> SEPARATOR <obj> SEPARATOR PADDING
	private byte[][] encryptValues(BigInteger n, byte[] key, byte[]... values) {
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0,
					Constants.SECRET_KEY_SPEC_LENGTH, Constants.KEY_ALGORITHM),
					new IvParameterSpec(this.iv));

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			// Add marker bytes.
			outputStream.write(this.cipher.update(Constants.TRIPLE_MARKER));

			if (values.length > 0) {

				int paddingLength = 0;

				// Encrypt all data parts and separate them with a corresponding
				// marker.
				for (int i = 0; i < values.length; ++i) {
					outputStream.write(this.cipher.update(values[i]));
					outputStream.write(this.cipher.update(Constants.SEPARATOR));
					paddingLength += values[i].length + 1;
				}

				// Add own padding.
				outputStream.write(this.cipher.update(Constants.PADDING, 0,
						Constants.BLOCK_SIZE
								- (paddingLength % Constants.BLOCK_SIZE)));
			}

			outputStream.write(this.cipher.doFinal());
			outputStream.close();

			return new byte[][] { outputStream.toByteArray(), key };
		}
		catch (Exception e) {
			// TODO: remove
			e.printStackTrace();
			return null;
		}
	}

	public byte[][] encryptMMM(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptMMM(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptMMM(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		return encryptValues(n,
				this.digester.digest(this.combFunc.combineNone(n, basicKey)),
				subject, predicate, object);
	}

	public byte[][] encryptMMP(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptMMP(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptMMP(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combineObject(n, basicKey, object));
		return encryptValues(n, encryptionKey, subject, predicate);
	}

	public byte[][] encryptMPM(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptMPM(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptMPM(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combinePredicate(n, basicKey, predicate));
		return encryptValues(n, encryptionKey, subject, object);
	}

	public byte[][] encryptPMM(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptPMM(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptPMM(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combineSubject(n, basicKey, subject));
		return encryptValues(n, encryptionKey, predicate, object);
	}

	public byte[][] encryptPPM(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptPPM(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptPPM(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combineSubjectAndPredicate(n, basicKey, subject, predicate));
		return encryptValues(n, encryptionKey, object);
	}

	public byte[][] encryptPMP(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptPMP(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptPMP(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combineSubjectAndObject(n, basicKey, subject, object));
		return encryptValues(n, encryptionKey, predicate);
	}

	public byte[][] encryptMPP(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptMPP(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptMPP(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc
				.combinePredicateAndObject(n, basicKey, predicate, object));
		return encryptValues(n, encryptionKey, subject);
	}

	public byte[][] encryptPPP(BigInteger n, byte[] basicKey, String subject,
			String predicate, String object) throws Exception {
		return this.encryptPPP(n, basicKey,
				subject.getBytes(Constants.STRING_CHARSET),
				predicate.getBytes(Constants.STRING_CHARSET),
				object.getBytes(Constants.STRING_CHARSET));
	}

	public byte[][] encryptPPP(BigInteger n, byte[] basicKey, byte[] subject,
			byte[] predicate, byte[] object) throws Exception {

		byte[] encryptionKey = this.digester.digest(this.combFunc.combineAll(n,
				basicKey, subject, predicate, object));
		return encryptValues(n, encryptionKey);
	}

}
