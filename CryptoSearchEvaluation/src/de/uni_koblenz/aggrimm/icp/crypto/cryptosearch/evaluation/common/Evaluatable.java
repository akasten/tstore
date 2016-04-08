package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common;

import java.math.BigInteger;

public abstract class Evaluatable<Q extends Query> {
	
	protected QueriedDocument document;
	
	protected Evaluatable(QueriedDocument document) {
		this.document = document;
	}

	public abstract boolean loadDocument(byte[] iv);

	public abstract boolean encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv);

	public abstract boolean performQuery(Q query);

	public abstract boolean initialize();

	public abstract boolean reset();

	public QueriedDocument getQueriedDocument() {
		return this.document;
	}

	public void setQueriedDocument(QueriedDocument document) {
		this.document = document;
	}
}
