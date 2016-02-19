package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CombiningFunction;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index.Graph;

public class FileQuerier {

	private CombiningFunction combFunc;
	private MessageDigest digester;

	public FileQuerier() throws CryptoException {
		try {
			this.combFunc = new CombiningFunction();
			this.digester = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
		}
		catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
	}

	public Iterator<String[]> queryQQQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {

		return new AbstractQueryResultIterator<String[]>(n, iv, queriedGraph,
				idSet) {

			private byte[] decryptionKey = digester.digest(patternKey);

			@Override
			public String[] next() {
				try {
					int cID = this.idSetIter.next();

					return this.decrypter
							.decryptWithDecryptionKey(this.n,
									this.queriedGraph.getCiphertext(cID),
									decryptionKey);
				}
				catch (Exception e) {
					e.printStackTrace();
					throw new NoSuchElementException(e.getMessage());
				}
			}
		};
	}

	public Iterator<String> queryRRQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {

		return new ScalarQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String> queryURQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedSubject) throws IOException,
			CryptoException {

		return queryRRQ(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineSubject(n,
						patternKey, queriedSubject)));
	}

	public Iterator<String> queryRUQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedPredicate)
			throws IOException, CryptoException {

		return queryRRQ(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combinePredicate(n,
						patternKey, queriedPredicate)));
	}

	public Iterator<String> queryUUQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedSubject,
			byte[] queriedPredicate) throws IOException, CryptoException {

		return queryRRQ(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineSubjectAndPredicate(
						n, patternKey, queriedSubject, queriedPredicate)));
	}

	public Iterator<String> queryRQR(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {
		return new ScalarQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String> queryUQR(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedSubject) throws IOException,
			CryptoException {

		return queryRQR(n, iv, queriedGraph, idSet,
				this.combFunc.combineSubject(n, patternKey, queriedSubject));
	}

	public Iterator<String> queryRQU(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedObject) throws IOException,
			CryptoException {

		return queryRQR(n, iv, queriedGraph, idSet,
				this.combFunc.combineObject(n, patternKey, queriedObject));
	}

	public Iterator<String> queryUQU(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedSubject, byte[] queriedObject)
			throws IOException, CryptoException {

		return queryRQR(n, iv, queriedGraph, idSet,
				this.combFunc.combineSubjectAndObject(n, patternKey,
						queriedSubject, queriedObject));
	}

	public Iterator<String> queryQRR(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {
		return new ScalarQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String> queryQUR(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedPredicate)
			throws IOException, CryptoException {

		return queryQRR(n, iv, queriedGraph, idSet,
				this.combFunc.combinePredicate(n, patternKey, queriedPredicate));
	}

	public Iterator<String> queryQRU(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedObject) throws IOException,
			CryptoException {

		return queryQRR(n, iv, queriedGraph, idSet,
				this.combFunc.combineObject(n, patternKey, queriedObject));
	}

	public Iterator<String> queryQUU(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedPredicate,
			byte[] queriedObject) throws IOException, CryptoException {

		return queryQRR(n, iv, queriedGraph, idSet,
				this.combFunc.combinePredicateAndObject(n, patternKey,
						queriedPredicate, queriedObject));
	}

	public Iterator<String[]> queryRQQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {

		return new TupleQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String[]> queryUQQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedSubject) throws IOException,
			CryptoException {

		return queryRQQ(n, iv, queriedGraph, idSet,
				this.combFunc.combineSubject(n, patternKey, queriedSubject));
	}

	public Iterator<String[]> queryQRQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws IOException, CryptoException {

		return new TupleQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String[]> queryQUQ(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedPredicate)
			throws IOException, CryptoException {

		return queryQRQ(n, iv, queriedGraph, idSet,
				this.combFunc.combinePredicate(n, patternKey, queriedPredicate));
	}

	public Iterator<String[]> queryQQR(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet, final byte[] patternKey)
			throws FileNotFoundException, CryptoException {

		return new TupleQueryResultIterator(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineNone(n, patternKey)));
	}

	public Iterator<String[]> queryQQU(final BigInteger n, byte[] iv,
			Graph queriedGraph, Iterable<Integer> idSet,
			final byte[] patternKey, byte[] queriedObject) throws IOException,
			CryptoException {

		return queryQQR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineObject(n, patternKey,
						queriedObject)));
	}

	public boolean queryRRR(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey) {

		return idSet.iterator().hasNext();
	}

	public boolean queryURR(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedSubject) throws IOException, CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineSubject(n,
						patternKey, queriedSubject)));
	}

	public boolean queryRUR(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedPredicate) throws IOException, CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combinePredicate(n,
						patternKey, queriedPredicate)));
	}

	public boolean queryRRU(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedObject) throws IOException, CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineObject(n, patternKey,
						queriedObject)));
	}

	public boolean queryUUR(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedSubject, byte[] queriedPredicate) throws IOException,
			CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineSubjectAndPredicate(
						n, patternKey, queriedSubject, queriedPredicate)));
	}

	public boolean queryURU(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedSubject, byte[] queriedObject) throws IOException,
			CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineSubjectAndObject(n,
						patternKey, queriedSubject, queriedObject)));
	}

	public boolean queryRUU(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedPredicate, byte[] queriedObject) throws IOException,
			CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combinePredicateAndObject(n,
						patternKey, queriedPredicate, queriedObject)));
	}

	public boolean queryUUU(final BigInteger n, byte[] iv, Graph queriedGraph,
			Iterable<Integer> idSet, final byte[] patternKey,
			byte[] queriedSubject, byte[] queriedPredicate, byte[] queriedObject)
			throws IOException, CryptoException {

		return queryRRR(n, iv, queriedGraph, idSet,
				this.digester.digest(this.combFunc.combineAll(n, patternKey,
						queriedSubject, queriedPredicate, queriedObject)));
	}

}
