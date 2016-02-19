package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;

public class CombiningFunction {

	private MessageDigest digester;

	public CombiningFunction() throws CryptoException {
		try {
			this.digester = MessageDigest
					.getInstance(Constants.COMBINING_HASH_ALGORITHM);
		}
		catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}

	public byte[] combineNone(BigInteger n, byte[] base) {
		return new BigInteger(base).mod(n).toByteArray();
	}

	public byte[] combineSubject(BigInteger n, byte[] base, String subject) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.SUBJECT_PADDING,
						subject.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combineSubject(BigInteger n, byte[] base, byte[] subject) {
		return combineValues(n, base,
				addPrefix(Constants.SUBJECT_PADDING, subject));
	}

	public byte[] combinePredicate(BigInteger n, byte[] base, String predicate) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.PREDICATE_PADDING,
						predicate.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combinePredicate(BigInteger n, byte[] base, byte[] predicate) {
		return combineValues(n, base,
				addPrefix(Constants.PREDICATE_PADDING, predicate));
	}

	public byte[] combineObject(BigInteger n, byte[] base, String object) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.OBJECT_PADDING,
						object.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combineObject(BigInteger n, byte[] base, byte[] object) {
		return combineValues(n, base,
				addPrefix(Constants.OBJECT_PADDING, object));
	}

	public byte[] combineSubjectAndObject(BigInteger n, byte[] base,
			String subject, String object) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.SUBJECT_PADDING,
						subject.getBytes(Constants.STRING_CHARSET)),
				addPrefix(Constants.OBJECT_PADDING,
						object.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combineSubjectAndObject(BigInteger n, byte[] base,
			byte[] subject, byte[] object) {
		return combineValues(n, base,
				addPrefix(Constants.SUBJECT_PADDING, subject),
				addPrefix(Constants.OBJECT_PADDING, object));
	}

	public byte[] combineSubjectAndPredicate(BigInteger n, byte[] base,
			byte[] subject, byte[] predicate) {
		return combineValues(n, base,
				addPrefix(Constants.SUBJECT_PADDING, subject),
				addPrefix(Constants.PREDICATE_PADDING, predicate));
	}

	public byte[] combineSubjectAndPredicate(BigInteger n, byte[] base,
			String subject, String predicate) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.SUBJECT_PADDING,
						subject.getBytes(Constants.STRING_CHARSET)),
				addPrefix(Constants.PREDICATE_PADDING,
						predicate.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combinePredicateAndObject(BigInteger n, byte[] base,
			byte[] predicate, byte[] object) {
		return combineValues(n, base,
				addPrefix(Constants.PREDICATE_PADDING, predicate),
				addPrefix(Constants.OBJECT_PADDING, object));
	}

	public byte[] combinePredicateAndObject(BigInteger n, byte[] base,
			String predicate, String object) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.PREDICATE_PADDING,
						predicate.getBytes(Constants.STRING_CHARSET)),
				addPrefix(Constants.OBJECT_PADDING,
						object.getBytes(Constants.STRING_CHARSET)));
	}

	public byte[] combineAll(BigInteger n, byte[] base, byte[] subject,
			byte[] predicate, byte[] object) {
		return combineValues(n, base,
				addPrefix(Constants.SUBJECT_PADDING, subject),
				addPrefix(Constants.PREDICATE_PADDING, predicate),
				addPrefix(Constants.OBJECT_PADDING, object));
	}

	public byte[] combineAll(BigInteger n, byte[] base, String subject,
			String predicate, String object) {
		return combineValues(
				n,
				base,
				addPrefix(Constants.SUBJECT_PADDING,
						subject.getBytes(Constants.STRING_CHARSET)),
				addPrefix(Constants.PREDICATE_PADDING,
						predicate.getBytes(Constants.STRING_CHARSET)),
				addPrefix(Constants.OBJECT_PADDING,
						object.getBytes(Constants.STRING_CHARSET)));
	}

	private byte[] combineValues(BigInteger n, byte[] base, byte[]... input) {
		try {
			BigInteger baseInt = new BigInteger(base).mod(n);

			for (byte[] barr : input) {
				baseInt = baseInt.multiply(
						baseInt.modPow(new BigInteger(barr), n)).mod(n);
			}

			return baseInt.toByteArray();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private byte[] addPrefix(byte[] prefix, byte[] uri) {
		byte[] prefixed = new byte[Constants.BLOCK_SIZE + uri.length];

		System.arraycopy(prefix, 0, prefixed, 0, Constants.BLOCK_SIZE);
		System.arraycopy(uri, 0, prefixed, Constants.BLOCK_SIZE, uri.length);

		return this.digester.digest(prefixed);
	}
}
