package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common;

import java.io.FileNotFoundException;
import java.math.BigInteger;

public class Evaluator<Q extends Query> {

	private Evaluatable<Q> store;

	public Evaluator(Evaluatable<Q> store) {
		this.store = store;
	}

	public long initialize() {
		return initialize(1);
	}

	public long loadDocument(byte[] iv) throws FileNotFoundException {
		return loadDocument(iv, 1);
	}

	public long initialize(int numberOfRuns) {
		long runtime = 0;
		boolean res = true;

		for (int i = 0; i < numberOfRuns; ++i) {
			long start = System.nanoTime();
			res &= this.store.initialize();
			runtime += (System.nanoTime() - start);
		}

		return res ? (runtime / numberOfRuns) : -1;
	}

	public long loadDocument(byte[] iv, int numberOfRuns)
			throws FileNotFoundException {
		long runtime = 0;
		boolean res = true;

		for (int i = 0; i < numberOfRuns; ++i) {
			res &= this.store.reset();
			long start = System.nanoTime();
			res &= this.store.loadDocument(iv);
			runtime += (System.nanoTime() - start);
		}

		return res ? (runtime / numberOfRuns) : -1;
	}

	public long encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv)
			throws FileNotFoundException {
		return encryptFile(n, basicKeys, iv, 1);
	}

	public long encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv,
			int numberOfRuns) throws FileNotFoundException {
		long runtime = 0;
		boolean res = true;

		for (int i = 0; i < numberOfRuns; ++i) {
			long start = System.nanoTime();
			res &= this.store.encryptFile(n, basicKeys, iv);
			runtime += (System.nanoTime() - start);
		}

		return res ? (runtime / numberOfRuns) : -1;
	}

	public long performQuery(Q... query) {
		return performQuery(1, query);
	}

	public long performQuery(int numberOfRuns, Q... query) {
		long runtime = 0;

		boolean res = true;

		for (int i = 0; i < numberOfRuns; ++i) {
			long start = System.nanoTime();
			for (Q q : query)
				res &= this.store.performQuery(q);
			runtime += (System.nanoTime() - start);
		}

		return res ? (runtime / numberOfRuns) : -1;
	}
}
