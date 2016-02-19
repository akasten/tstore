package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;

public class TupleQueryResultIterator extends AbstractQueryResultIterator<String[]> {

	private String[] nextResult;

	private int tripleType;

	private byte[] patternKey;

	public TupleQueryResultIterator(BigInteger n, String encryptedFile, byte[] iv, int tripleType,
			byte[] patternKey) throws FileNotFoundException, CryptoException {
		super(n, encryptedFile, iv);
		this.tripleType = tripleType;
		this.patternKey = patternKey;
		this.nextResult = getNext();
	}

	public TupleQueryResultIterator(BigInteger n, TripleReader encryptedFile, byte[] iv,
			int tripleType, byte[] patternKey) throws CryptoException {
		super(n, encryptedFile, iv);
		this.tripleType = tripleType;
		this.patternKey = patternKey;
		this.nextResult = getNext();
	}

	private String[] getNext() throws NoSuchElementException {
		try {
			String[] res;
			byte[][] triple;

			while (tripleReader.hasNext()) {
				triple = tripleReader.readTriple();
				res = decrypter.decryptWithPatternKey(this.n, triple[this.tripleType], patternKey);

				if (res != null && res[0] != null)
					return new String[] { res[0], res[1] };
			}

			return null;
		}
		catch (Exception e) {
			throw new NoSuchElementException(e.getMessage());
		}
	}

	@Override
	public String[] next() {
		String[] next = this.nextResult;
		this.nextResult = getNext();
		return next;
	}

	@Override
	public boolean hasNext() {
		return this.nextResult != null;
	}
}
