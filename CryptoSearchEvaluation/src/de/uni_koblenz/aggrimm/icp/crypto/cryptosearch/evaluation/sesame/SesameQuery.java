package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.sesame;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.Query;

public class SesameQuery implements Query {

	private String sparqlQuery;

	public SesameQuery(String sparqlQuery) {
		this.sparqlQuery = sparqlQuery;
	}

	public String getSparqlQuery() {
		return sparqlQuery;
	}

	public void setSparqlQuery(String sparqlQuery) {
		this.sparqlQuery = sparqlQuery;
	}

	@Override
	public String toString() {
		return this.sparqlQuery;
	}
}
