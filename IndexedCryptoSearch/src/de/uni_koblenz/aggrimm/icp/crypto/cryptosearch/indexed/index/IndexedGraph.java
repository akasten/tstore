package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index;

import java.io.File;
import java.io.IOException;
import java.util.List;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.PatternTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoBase;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.query.TriplePattern;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query.FileQuerier;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query.QueryResult;

public class IndexedGraph extends CryptoBase {

	private Graph graph;
	private IndexTree index;

	IndexedGraph(Graph graph, IndexTree index) throws Exception {
		super(index.getIv());

		this.graph = graph;
		this.index = index;
	}

	public static IndexedGraph loadIndexedGraph(String graphFileName,
			String indexFileName, byte[] iv) throws Exception {

		return new IndexedGraph(Graph.loadGraph(graphFileName),
				IndexTree.loadIndexTree(indexFileName, iv));
	}

	public static IndexedGraph loadIndexedGraph(File graphFile, File indexFile,
			byte[] iv) throws Exception {

		return new IndexedGraph(Graph.loadGraph(graphFile),
				IndexTree.loadIndexTree(indexFile, iv));
	}
	
	public Graph getGraph() {
		return this.graph;
	}
	
	public IndexTree getIndex() {
		return this.index;
	}

	public void writeToFile(String graphFileName, String indexFileName)
			throws IOException {
		this.graph.writeToFile(graphFileName);
		this.index.writeToFile(indexFileName);
	}

	public void writeToFile(File graphFile, File indexFile) throws IOException {
		this.graph.writeToFile(graphFile);
		this.index.writeToFile(indexFile);
	}

	public QueryResult performQuery(List<TriplePattern> triplePatterns)
			throws IOException, CryptoException {
		QueryResult result = new QueryResult();
		FileQuerier querier = new FileQuerier();

		byte[] iv = this.index.getIv();

		for (TriplePattern pattern : triplePatterns) {
			if (pattern.patternType == PatternTypes.RRR) {

				byte[] decryptionKey = this.digester.digest(pattern.patternKey);
				Iterable<Integer> idSet = this.index
						.getCiphertextIds(decryptionKey);

				if (!querier.queryRRR(pattern.n, iv, this.graph, idSet,
						pattern.patternKey))
					return result;
			}
		}

		for (TriplePattern pattern : triplePatterns) {

			byte[] decryptionKey = this.digester.digest(pattern.patternKey);
			Iterable<Integer> idSet = this.index
					.getCiphertextIds(decryptionKey);

			switch (pattern.patternType) {
				case PatternTypes.RRR:
					// Do nothing since these queries are already handled.
					break;
				case PatternTypes.QQQ:
					result = result.join(querier.queryQQQ(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.subjectVar, pattern.predicateVar,
							pattern.objectVar);
					break;
				case PatternTypes.RQQ:
					result = result.join(querier.queryRQQ(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.predicateVar, pattern.objectVar);
					break;
				case PatternTypes.QRQ:
					result = result.join(querier.queryQRQ(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.subjectVar, pattern.objectVar);
					break;
				case PatternTypes.QQR:
					result = result.join(querier.queryQQR(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.subjectVar, pattern.predicateVar);
					break;
				case PatternTypes.QRR:
					result = result.join(querier.queryQRR(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.subjectVar);
					break;
				case PatternTypes.RQR:
					result = result.join(querier.queryRQR(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.predicateVar);
					break;
				case PatternTypes.RRQ:
					result = result.join(querier.queryRRQ(pattern.n, iv,
							this.graph, idSet, pattern.patternKey),
							pattern.objectVar);
					break;
			}
		}

		return result;
	}

}
