package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;

public class ScalarQueryResultIterator extends AbstractQueryResultIterator<String> {

	private String nextResult;

	private int tripleType;

	private byte[] patternKey;

	public ScalarQueryResultIterator(BigInteger n, String encryptedFile, byte[] iv, int tripleType,
			byte[] patternKey) throws FileNotFoundException, CryptoException {
		super(n, encryptedFile, iv);
		this.tripleType = tripleType;
		this.patternKey = patternKey;
		this.nextResult = getNext();
	}

	public ScalarQueryResultIterator(BigInteger n, TripleReader encryptedReader, byte[] iv,
			int tripleType, byte[] patternKey) throws CryptoException {
		super(n, encryptedReader, iv);
		this.tripleType = tripleType;
		this.patternKey = patternKey;
		this.nextResult = getNext();
	}

	private String getNext() throws NoSuchElementException {
		try {
			String[] res;
			byte[][] triple;

			while (this.tripleReader.hasNext()) {
				triple = this.tripleReader.readTriple();
				res = this.decrypter.decryptWithPatternKey(this.n, triple[this.tripleType],
						this.patternKey);

				if (res != null && res[0] != null)
					return res[0];
			}

			return null;
		}
		catch (Exception e) {
			throw new NoSuchElementException(e.getMessage());
		}
	}

	@Override
	public String next() {
		String next = this.nextResult;
		this.nextResult = getNext();
		return next;
	}

	@Override
	public boolean hasNext() {
		return this.nextResult != null;
	}
}