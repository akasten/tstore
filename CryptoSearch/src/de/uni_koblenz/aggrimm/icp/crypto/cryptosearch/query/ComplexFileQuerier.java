package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.PatternTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.query.TriplePattern;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;

public class ComplexFileQuerier {

	public QueryResult performQuery(BigInteger n,
			List<TriplePattern> triplePatterns, String encryptedFile, byte[] iv)
			throws IOException, CryptoException {
		QueryResult result = new QueryResult();
		FileQuerier querier = new FileQuerier();

		for (TriplePattern pattern : triplePatterns) {
			if (pattern.patternType == PatternTypes.RRR)
				if (!querier.queryRRR(n, encryptedFile, iv, pattern.patternKey))
					return result;
		}

		for (TriplePattern pattern : triplePatterns) {
			switch (pattern.patternType) {
				case PatternTypes.RRR:
					// Do nothing since these queries are already handled.
					break;
				case PatternTypes.QQQ:
					result = result.join(querier.queryQQQ(n, encryptedFile, iv,
							pattern.patternKey), pattern.subjectVar,
							pattern.predicateVar, pattern.objectVar);
					break;
				case PatternTypes.RQQ:
					result = result.join(querier.queryRQQ(n, encryptedFile, iv,
							pattern.patternKey), pattern.predicateVar,
							pattern.objectVar);
					break;
				case PatternTypes.QRQ:
					result = result.join(querier.queryQRQ(n, encryptedFile, iv,
							pattern.patternKey), pattern.subjectVar, pattern.objectVar);
					break;
				case PatternTypes.QQR:
					result = result.join(querier.queryQQR(n, encryptedFile, iv,
							pattern.patternKey), pattern.subjectVar,
							pattern.predicateVar);
					break;
				case PatternTypes.QRR:
					result = result.join(querier.queryQRR(n, encryptedFile, iv,
							pattern.patternKey), pattern.subjectVar);
					break;
				case PatternTypes.RQR:
					result = result.join(querier.queryRQR(n, encryptedFile, iv,
							pattern.patternKey), pattern.predicateVar);
					break;
				case PatternTypes.RRQ:
					result = result.join(querier.queryRRQ(n, encryptedFile, iv,
							pattern.patternKey), pattern.objectVar);
					break;
			}
		}

		return result;
	}

	public QueryResult performQuery(BigInteger n,
			List<TriplePattern> triplePatterns, TripleReader encryptedFile,
			byte[] iv) throws IOException, CryptoException {
		try {
			QueryResult result = new QueryResult();
			FileQuerier querier = new FileQuerier();

			for (TriplePattern pattern : triplePatterns) {
				if (pattern.patternType == PatternTypes.RRR) {
					if (!querier.queryRRR(n, encryptedFile, iv, pattern.patternKey))
						return result;
				}
			}

			for (TriplePattern pattern : triplePatterns) {
				switch (pattern.patternType) {
					case PatternTypes.RRR:
						// Do nothing since these queries are already handled.
						break;
					case PatternTypes.QQQ:
						result = result.join(querier.queryQQQ(n, encryptedFile,
								iv, pattern.patternKey), pattern.subjectVar,
								pattern.predicateVar, pattern.objectVar);
						break;
					case PatternTypes.RQQ:
						result = result.join(querier.queryRQQ(n, encryptedFile,
								iv, pattern.patternKey), pattern.predicateVar,
								pattern.objectVar);
						break;
					case PatternTypes.QRQ:
						result = result.join(querier.queryQRQ(n, encryptedFile,
								iv, pattern.patternKey), pattern.subjectVar,
								pattern.objectVar);
						break;
					case PatternTypes.QQR:
						result = result.join(querier.queryQQR(n, encryptedFile,
								iv, pattern.patternKey), pattern.subjectVar,
								pattern.predicateVar);
						break;
					case PatternTypes.QRR:
						result = result.join(querier.queryQRR(n, encryptedFile,
								iv, pattern.patternKey), pattern.subjectVar);
						break;
					case PatternTypes.RQR:
						result = result.join(querier.queryRQR(n, encryptedFile,
								iv, pattern.patternKey), pattern.predicateVar);
						break;
					case PatternTypes.RRQ:
						result = result.join(querier.queryRRQ(n, encryptedFile,
								iv, pattern.patternKey), pattern.objectVar);
						break;
				}
			}

			return result;
		}
		catch (IOException e) {
			e.printStackTrace();
			throw new CryptoException(e);
		}
	}
}
