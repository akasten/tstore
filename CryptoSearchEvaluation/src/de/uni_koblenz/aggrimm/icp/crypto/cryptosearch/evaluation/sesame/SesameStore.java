package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.sesame;

import java.io.File;
import java.math.BigInteger;

import org.openrdf.model.Resource;
import org.openrdf.query.MalformedQueryException;
import org.openrdf.query.QueryEvaluationException;
import org.openrdf.query.QueryLanguage;
import org.openrdf.query.TupleQuery;
import org.openrdf.query.TupleQueryResult;
import org.openrdf.repository.Repository;
import org.openrdf.repository.RepositoryConnection;
import org.openrdf.repository.RepositoryException;
import org.openrdf.repository.sail.SailRepository;
import org.openrdf.rio.RDFFormat;
import org.openrdf.sail.memory.MemoryStore;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.Evaluatable;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.QueriedDocument;

public class SesameStore extends Evaluatable<SesameQuery> {

	private Repository store;

	public SesameStore(QueriedDocument document) {
		super(document);
		this.store = new SailRepository(new MemoryStore());
	}

	@Override
	public boolean loadDocument(byte[] iv) {
		try {
			RepositoryConnection con = store.getConnection();
			File file = new File(document.getPlainTextFileName());
			con.add(file, null, RDFFormat.NTRIPLES);
			con.close();

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv) {
		return false;
	}

	@Override
	public boolean performQuery(SesameQuery query) {
		try {
			RepositoryConnection con = this.store.getConnection();

			TupleQuery tupleQuery = con.prepareTupleQuery(QueryLanguage.SPARQL,
					query.getSparqlQuery());
			TupleQueryResult result = tupleQuery.evaluate();

			// int size = 0;
			// Since Sesame uses lazy evaluation, all query results are iterated
			// in order to get a better comparison.
			while (result.hasNext()) {
				result.next();
				// BindingSet set = result.next();
				// System.out.println(set.getValue("x") + " " +
				// set.getValue("y") + " " + set.getValue("z"));
				// ++size;
			}
			result.close();
			con.close();

			// System.out.println("  Number of results: " + size);

			return true;
		}
		catch (RepositoryException e) {
			e.printStackTrace();
			return false;
		}
		catch (MalformedQueryException e) {
			e.printStackTrace();
			return false;
		}
		catch (QueryEvaluationException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean initialize() {
		try {
			this.store.initialize();
			return true;
		}
		catch (RepositoryException e) {
			return false;
		}
	}

	@Override
	public boolean reset() {
		try {
			RepositoryConnection con = this.store.getConnection();
			con.remove((Resource) null, null, null);
			con.close();

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

}
