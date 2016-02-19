package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.query;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.openrdf.query.MalformedQueryException;
import org.openrdf.query.algebra.StatementPattern;
import org.openrdf.query.algebra.TupleExpr;
import org.openrdf.query.algebra.Var;
import org.openrdf.query.algebra.helpers.StatementPatternCollector;
import org.openrdf.query.parser.ParsedQuery;
import org.openrdf.query.parser.sparql.SPARQLParser;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.BasicTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.PatternTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;

/**
 * This class provides different static factory methods for creating triple
 * patterns from SPARQL query strings.
 * 
 * @author Andreas Kasten
 * 
 */
public class QueryFactory {

	/**
	 * Used for parsing the query strings.
	 */
	private static SPARQLParser parser = new SPARQLParser();

	/**
	 * The constructor is set to private in order to prohibit the creation of
	 * unnecessary instances.
	 */
	private QueryFactory() {
	}

	/**
	 * Creates a list of query patterns based on the given array of basic keys
	 * and the given SPARQL query string. If the parsing process fails, an
	 * exception is thrown.
	 * <p>
	 * The basic keys are directly used to create the query keys of the query
	 * patterns. This method can only be used if the data owner does not define
	 * any restrictions and the user can specify all necessary query parts.
	 * <p>
	 * Although the given query string may contain any valid SPARQL query, the
	 * returned query patterns only consider the triple patterns of this query.
	 * All other parts of the query such as FILTER operations are ignored.
	 * Furthermore, all triple patterns of the query string are handled equally,
	 * independent of their occurrence. I.e., different graph patterns, UNION
	 * between different graph patterns, OPTIONAL group patterns, etc. are
	 * ignored.
	 * 
	 * @param basicKeys
	 *            The basic keys to be used for creating the query keys of the
	 *            query patterns.
	 * @param sparqlQuery
	 *            The SPARQL query string.
	 * @return A list of all query patterns extracted from the query string.
	 * @throws CryptoException
	 *             Will be thrown if the parsing process fails.
	 */
	public static List<TriplePattern> createQuery(BigInteger n,
			byte[][] basicKeys, String sparqlQuery) throws CryptoException {
		try {
			// Use the sesame SPARQL parser to retrieve all statement patterns
			// of the query. This is done using the visitor pattern. In this
			// case, the visitor is the statement collector.
			ParsedQuery query = parser.parseQuery(sparqlQuery, null);
			StatementPatternCollector collector = new StatementPatternCollector();
			query.getTupleExpr().visit(collector);
			List<StatementPattern> patterns = collector.getStatementPatterns();

			// The list of query patterns to be returned.
			List<TriplePattern> result = new ArrayList<TriplePattern>(
					patterns.size());

			for (StatementPattern pattern : patterns) {

				// Retrieve all parts of the query.
				Var s = pattern.getSubjectVar();
				Var p = pattern.getPredicateVar();
				Var o = pattern.getObjectVar();

				// Marks whether or not the subject, predicate, and object are
				// bound.
				boolean sb, pb, ob;

				// Store the parts of the triple pattern.
				String subject, predicate, object;
				int patternType = 0;
				byte[] basicKey;

				// Set the subject of the query. It may either be a URI or a
				// variable.
				if (sb = s.hasValue())
					subject = s.getValue().stringValue();
				else
					subject = "?" + s.getName();

				// Set the predicate of the query. It may either be a URI or a
				// variable.
				if (pb = p.hasValue())
					predicate = p.getValue().stringValue();
				else
					predicate = "?" + p.getName();

				// Set the object of the query. It may either be a URI or a
				// variable.
				if (ob = o.hasValue())
					object = o.getValue().stringValue();
				else
					object = "?" + o.getName();

				// Set the query type and the basic key depending on the
				// combinations of the subject, predicate, and object. The
				// combination of the query parameter and the query key is done
				// in the constructor of the corresponding class.
				if (sb && pb && ob) {
					patternType = PatternTypes.UUU;
					basicKey = basicKeys[BasicTypes.PPP];
				}
				else if (!sb && pb && ob) {
					patternType = PatternTypes.QUU;
					basicKey = basicKeys[BasicTypes.MPP];
				}
				else if (sb && !pb && ob) {
					patternType = PatternTypes.UQU;
					basicKey = basicKeys[BasicTypes.PMP];
				}
				else if (sb && pb && !ob) {
					patternType = PatternTypes.UUQ;
					basicKey = basicKeys[BasicTypes.PPM];
				}
				else if (!sb && !pb && ob) {
					patternType = PatternTypes.QQU;
					basicKey = basicKeys[BasicTypes.MMP];
				}
				else if (!sb && pb && !ob) {
					patternType = PatternTypes.QUQ;
					basicKey = basicKeys[BasicTypes.MPM];
				}
				else if (sb && !pb && !ob) {
					patternType = PatternTypes.UQQ;
					basicKey = basicKeys[BasicTypes.PMM];
				}
				else { // if (!sb && !pb && !ob)
					patternType = PatternTypes.QQQ;
					basicKey = basicKeys[BasicTypes.MMM];
				}

				// Create a new query pattern and add it to the result.
				result.add(new TriplePattern(n, basicKey, patternType, subject,
						predicate, object));
			}

			return result;

		}
		catch (MalformedQueryException e) {
			throw new CryptoException(e);
		}
	}

	/**
	 * Creates a modified query string based on the given SPARQL query. The
	 * modified query string corresponds to a set of query patterns which would
	 * be created from the original SPARQL query. Thus, this method can be used
	 * for comparing query patterns with regular SPARQL queries.
	 * <p>
	 * The returned SPARQL string contains all triple patterns of the original
	 * one but puts them in one graph pattern. I.e., different graph patterns,
	 * UNION between different graph patterns, OPTIONAL group patterns, etc. are
	 * ignored. Additionally, other parts of the original query such as FILTER
	 * operations are ignored. Finally, all variables of all triple patterns are
	 * included in the list of variables to be returned.
	 * 
	 * @param sparqlQuery
	 *            The SPARQL query to be simplified.
	 * @return The simplified version of the original SPARQL query.
	 * @throws CryptoException
	 *             Will be thrown if the input query cannot correctly be parsed.
	 */
	public static String simplifyQuery(String sparqlQuery)
			throws CryptoException {
		try {
			// Use the sesame SPARQL parser to retrieve all statement patterns
			// of the query. This is done using the visitor pattern. In this
			// case, the visitor is the statement collector.
			ParsedQuery query = parser.parseQuery(sparqlQuery, null);
			StatementPatternCollector collector = new StatementPatternCollector();
			TupleExpr tupleExpression = query.getTupleExpr();

			// Store a string of all triple patterns.
			String triplePatterns = "";

			// Store all variable names included in all query patterns.
			Set<String> varNames = new HashSet<String>();

			// Extract all query patterns.
			tupleExpression.visit(collector);
			List<StatementPattern> patterns = collector.getStatementPatterns();
			for (StatementPattern pattern : patterns) {

				// Retrieve all parts of the query.
				Var s = pattern.getSubjectVar();
				Var p = pattern.getPredicateVar();
				Var o = pattern.getObjectVar();

				// Store the values of the query parts.
				String subject, predicate, object;

				// Set the subject of the query. It may either be a URI or a
				// variable.
				if (s.hasValue())
					subject = "<" + s.getValue().stringValue() + ">";
				else {
					subject = "?" + s.getName();
					varNames.add(subject);
				}

				// Set the predicate of the query. It may either be a URI or a
				// variable.
				if (p.hasValue())
					predicate = "<" + p.getValue().stringValue() + ">";
				else {
					predicate = "?" + p.getName();
					varNames.add(predicate);
				}

				// Set the object of the query. It may either be a URI or a
				// variable.
				if (o.hasValue())
					object = "<" + o.getValue().stringValue() + ">";
				else {
					object = "?" + o.getName();
					varNames.add(object);
				}

				// Add the triple pattern to the String containing all such
				// patterns.
				triplePatterns += "  " + subject + " " + predicate + " "
						+ object + " . \n";
			}

			// Create the prefix of the query.
			String selectString = "SELECT";
			for (String var : varNames)
				selectString += " " + var;

			// Create the complete query string and return the result.
			return selectString + " {\n" + triplePatterns + "}";
		}
		catch (MalformedQueryException e) {
			throw new CryptoException(e);
		}
	}
}
