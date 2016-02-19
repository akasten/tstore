package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Iterator;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.TripleDecrypter;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index.Graph;

public abstract class AbstractQueryResultIterator<T> implements Iterator<T> {

	protected TripleDecrypter decrypter;

	protected BigInteger n;

	protected Iterator<Integer> idSetIter;

	protected Graph queriedGraph;

	protected AbstractQueryResultIterator(BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet)
			throws FileNotFoundException, CryptoException {
		this.decrypter = new TripleDecrypter(iv);
		this.n = n;
		this.idSetIter = idSet.iterator();
		this.queriedGraph = queriedGraph;
	}

	@Override
	public boolean hasNext() {
		return idSetIter.hasNext();
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException("Operation not supported.");
	}

}
