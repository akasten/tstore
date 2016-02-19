package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.ClosableIterator;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.TripleDecrypter;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.FileTripleReader;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;

public abstract class AbstractQueryResultIterator<T> implements ClosableIterator<T> {

	protected TripleReader tripleReader;

	protected TripleDecrypter decrypter;
	
	protected BigInteger n;
	
	protected AbstractQueryResultIterator(BigInteger n, String encryptedFile, byte[] iv)
			throws FileNotFoundException, CryptoException {
		this.tripleReader = new FileTripleReader(encryptedFile);
		this.decrypter = new TripleDecrypter(iv);
		this.n = n;
	}

	protected AbstractQueryResultIterator(BigInteger n, TripleReader encryptedReader, byte[] iv)
			throws CryptoException {
		this.tripleReader = encryptedReader;
		this.decrypter = new TripleDecrypter(iv);
		this.n = n;
	}

	@Override
	public boolean hasNext() {
		return this.tripleReader.hasNext();
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException("Operation not supported.");
	}

	@Override
	public void close() throws IOException {
		this.tripleReader.close();
	}

}
