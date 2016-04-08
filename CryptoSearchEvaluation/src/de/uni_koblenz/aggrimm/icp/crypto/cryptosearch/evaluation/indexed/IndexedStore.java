package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.indexed;

import java.math.BigInteger;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.Evaluatable;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.QueriedDocument;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index.IndexFactory;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index.IndexedGraph;

public class IndexedStore extends Evaluatable<IndexedQuery> {

	private IndexedGraph graph;

	public IndexedStore(QueriedDocument document) {
		super(document);
	}

	@Override
	public boolean loadDocument(byte[] iv) {
		try {
			graph = IndexedGraph.loadIndexedGraph(
					this.document.getEncryptedIndexedFileName(),
					this.document.getIndexFileName(), iv);

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv) {
		try {
			IndexFactory indexFactory = new IndexFactory(iv);

			this.graph = indexFactory.encryptPlaintextGraph(n, basicKeys,
					this.document.getPlainTextFileName());

			this.graph.writeToFile(this.document.getEncryptedIndexedFileName(),
					this.document.getIndexFileName());

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean performQuery(IndexedQuery query) {
		try {
			this.graph.performQuery(query.getQueryPatterns());

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean initialize() {
		return false;
	}

	@Override
	public boolean reset() {
		return true;
	}

}
