package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index.Graph;

public class TupleQueryResultIterator extends
		AbstractQueryResultIterator<String[]> {

	private String[] nextResult;

	private byte[] decryptionKey;

	public TupleQueryResultIterator(BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, byte[] decryptionKey)
			throws FileNotFoundException, CryptoException {
		super(n, iv, queriedGraph, idSet);
		this.decryptionKey = decryptionKey;
		this.nextResult = getNext();
	}

	private String[] getNext() throws NoSuchElementException {
		try {
			if (!this.idSetIter.hasNext())
				return null;

			byte[] triple = this.queriedGraph.getCiphertext(this.idSetIter
					.next());

			String[] res = decrypter.decryptWithDecryptionKey(this.n, triple,
					this.decryptionKey);

			if (res != null && res[0] != null)
				return new String[] { res[0], res[1] };

			return null;
		}
		catch (Exception e) {
			e.printStackTrace();

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
