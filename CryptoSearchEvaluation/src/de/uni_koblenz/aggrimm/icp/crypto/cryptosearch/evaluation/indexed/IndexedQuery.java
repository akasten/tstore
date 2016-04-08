package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.indexed;

import java.math.BigInteger;
import java.util.List;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.query.TriplePattern;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.Query;

public class IndexedQuery implements Query {
	
	private List<TriplePattern> queryPatterns;

	private byte[] iv;

	private BigInteger n;

	public IndexedQuery(List<TriplePattern> queryPatterns, BigInteger n, byte[] iv) {
		this.queryPatterns = queryPatterns;
		this.iv = iv;
		this.n = n;
	}

	public List<TriplePattern> getQueryPatterns() {
		return queryPatterns;
	}

	public void removeAllQueryPatterns() {
		this.queryPatterns.removeAll(this.queryPatterns);
	}

	public void addQuerPattern(TriplePattern queryPattern) {
		this.queryPatterns.add(queryPattern);
	}

	public void setQueryPatterns(List<TriplePattern> queryPatterns) {
		this.queryPatterns = queryPatterns;
	}

	public int getQueryPatternCount() {
		return this.queryPatterns.size();
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public BigInteger getN() {
		return n;
	}

	public void setN(BigInteger n) {
		this.n = n;
	}
}
