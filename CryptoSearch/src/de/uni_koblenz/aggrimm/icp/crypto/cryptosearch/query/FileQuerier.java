package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.BasicTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.ClosableIterator;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CombiningFunction;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.TripleDecrypter;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.FileTripleReader;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;

public class FileQuerier {

	private CombiningFunction combFunc;

	public FileQuerier() throws CryptoException {
		this.combFunc = new CombiningFunction();
	}

	public ClosableIterator<String[]> queryQQQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new AbstractQueryResultIterator<String[]>(n, encryptedFile, iv) {

			@Override
			public String[] next() {
				try {
					byte[][] triple = tripleReader.readTriple();
					return decrypter.decryptWithPatternKey(this.n, triple[0], queryKey);
				}
				catch (Exception e) {
					e.printStackTrace();
					throw new NoSuchElementException(e.getMessage());
				}
			}
		};
	}

	public ClosableIterator<String> queryRRQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new ScalarQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.PPM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryURQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRRQ(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRUQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryRRQ(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryUUQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject, byte[] queriedPredicate) throws IOException,
			CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndPredicate(n,
				queryKey, queriedSubject, queriedPredicate);
		return queryRRQ(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRQR(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new ScalarQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.PMP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryUQR(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRQR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRQU(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryRQR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryUQU(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject, byte[] queriedObject) throws IOException,
			CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndObject(n, queryKey,
				queriedSubject, queriedObject);
		return queryRQR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQRR(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new ScalarQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.MPP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryQUR(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryQRR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQRU(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryQRR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQUU(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate, byte[] queriedObject) throws IOException,
			CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicateAndObject(n,
				queryKey, queriedPredicate, queriedObject);
		return queryQRR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryRQQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new TupleQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.PMM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryUQQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRQQ(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryQRQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws IOException, CryptoException {
		return new TupleQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.MPM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryQUQ(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryQRQ(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryQQR(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey)
			throws FileNotFoundException, CryptoException {
		return new TupleQueryResultIterator(n, encryptedFile, iv,
				BasicTypes.MMP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryQQU(final BigInteger n,
			String encryptedFile, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryQQR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryRRR(final BigInteger n, String encryptedFile,
			byte[] iv, byte[] queryKey) throws IOException, CryptoException {
		TripleReader encryptedReader = new FileTripleReader(encryptedFile);
		try {
			queryKey = combFunc.combineNone(n, queryKey);
			TripleDecrypter decrypter = new TripleDecrypter(iv);

			while (encryptedReader.hasNext()) {
				byte[][] triple = encryptedReader.readTriple();
				if (decrypter.decryptWithPatternKey(n, triple[7], queryKey) != null)
					return true;
			}

			return false;
		}
		catch (IOException e) {
			throw e;
		}
		catch (CryptoException e) {
			throw e;
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
		finally {
			encryptedReader.close();
		}
	}

	public boolean queryURR(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryRUR(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedPredicate)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryRRU(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedObject)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryUUR(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedPredicate) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndPredicate(n,
				queryKey, queriedSubject, queriedPredicate);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryURU(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndObject(n, queryKey,
				queriedSubject, queriedObject);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryRUU(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedPredicate,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicateAndObject(n,
				queryKey, queriedPredicate, queriedObject);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public boolean queryUUU(final BigInteger n, String encryptedFile,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedPredicate, byte[] queriedObject) throws IOException,
			CryptoException {
		byte[] decryptionKey = this.combFunc.combineAll(n, queryKey,
				queriedSubject, queriedPredicate, queriedObject);
		return queryRRR(n, encryptedFile, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryQQQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {

		return new AbstractQueryResultIterator<String[]>(n, encryptedReader, iv) {

			@Override
			public String[] next() {
				try {
					byte[][] triple = tripleReader.readTriple();
					return decrypter.decryptWithPatternKey(n, triple[0], queryKey);
				}
				catch (Exception e) {
					throw new NoSuchElementException(e.getMessage());
				}
			}
		};
	}

	public ClosableIterator<String> queryRRQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new ScalarQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.PPM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryURQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRRQ(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRUQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryRRQ(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryUUQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject, byte[] queriedPredicate)
			throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndPredicate(n,
				queryKey, queriedSubject, queriedPredicate);
		return queryRRQ(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRQR(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new ScalarQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.PMP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryUQR(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRQR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryRQU(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryRQR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryUQU(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject, byte[] queriedObject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndObject(n, queryKey,
				queriedSubject, queriedObject);
		return queryRQR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQRR(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new ScalarQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.MPP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String> queryQUR(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryQRR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQRU(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryQRR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String> queryQUU(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate, byte[] queriedObject)
			throws CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicateAndObject(n,
				queryKey, queriedPredicate, queriedObject);
		return queryQRR(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryRQQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new TupleQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.PMM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryUQQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedSubject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRQQ(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryQRQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new TupleQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.MPM, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryQUQ(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedPredicate) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryQRQ(n, encryptedReader, iv, decryptionKey);
	}

	public ClosableIterator<String[]> queryQQR(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey)
			throws CryptoException {
		return new TupleQueryResultIterator(n, encryptedReader, iv,
				BasicTypes.MMP, this.combFunc.combineNone(n, queryKey));
	}

	public ClosableIterator<String[]> queryQQU(BigInteger n,
			TripleReader encryptedReader, byte[] iv, final byte[] queryKey,
			byte[] queriedObject) throws CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryQQR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryRRR(BigInteger n, TripleReader encryptedReader,
			byte[] iv, byte[] queryKey) throws IOException, CryptoException {
		try {
			queryKey = combFunc.combineNone(n, queryKey);

			TripleDecrypter decrypter = new TripleDecrypter(iv);

			while (encryptedReader.hasNext()) {
				byte[][] triple = encryptedReader.readTriple();
				if (decrypter.decryptWithPatternKey(n, triple[7], queryKey) != null)
					return true;
			}

			return false;
		}
		catch (IOException e) {
			throw e;
		}
		catch (CryptoException e) {
			throw e;
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
		finally {
			encryptedReader.close();
		}
	}

	public boolean queryURR(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubject(n, queryKey,
				queriedSubject);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryRUR(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedPredicate)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicate(n, queryKey,
				queriedPredicate);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryRRU(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedObject)
			throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineObject(n, queryKey,
				queriedObject);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryUUR(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedPredicate) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndPredicate(n,
				queryKey, queriedSubject, queriedPredicate);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryURU(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combineSubjectAndObject(n, queryKey,
				queriedSubject, queriedObject);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryRUU(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedPredicate,
			byte[] queriedObject) throws IOException, CryptoException {
		byte[] decryptionKey = this.combFunc.combinePredicateAndObject(n,
				queryKey, queriedPredicate, queriedObject);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}

	public boolean queryUUU(BigInteger n, TripleReader encryptedReader,
			byte[] iv, final byte[] queryKey, byte[] queriedSubject,
			byte[] queriedPredicate, byte[] queriedObject) throws IOException,
			CryptoException {
		byte[] decryptionKey = this.combFunc.combineAll(n, queryKey,
				queriedSubject, queriedPredicate, queriedObject);
		return queryRRR(n, encryptedReader, iv, decryptionKey);
	}
}
