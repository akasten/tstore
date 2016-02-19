package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.query;

import java.math.BigInteger;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.PatternTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CombiningFunction;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;

/**
 * This class represents a single triple pattern which can be applied on an
 * encrypted file.
 * 
 * @author Andreas Kasten
 * 
 */
public class TriplePattern {

	/**
	 * The subject variable. Contains a variable name such as <code>"?x"</code>,
	 * a URI, or <code>null<code>. <code>"?x"</code> states that the subject is
	 * a return value of the query. A URI or
	 * <code>null<code> state that the subject is a query parameter. It this
	 * case, it is already encoded in the query key.
	 */
	public final String subjectVar;

	/**
	 * The predicate variable. Contains a variable name such as
	 * <code>"?y"</code>, a URI, or <code>null<code>. <code>"?y"</code> states
	 * that the predicate is a return value of the query. A URI or
	 * <code>null<code> state that the predicate is a query parameter. It
	 * this case, it is already encoded in the query key.
	 */
	public final String predicateVar;

	/**
	 * The object variable. Contains a variable name such as <code>"?z"</code>,
	 * a URI, or <code>null<code>. <code>"?z"</code> states that the object is a
	 * return value of the query. A URI or
	 * <code>null<code> state that the object is a query parameter. It this
	 * case, it is already encoded in the query key.
	 */
	public final String objectVar;

	/**
	 * The pattern key, already containing the user pattern. This pattern key
	 * can directly be transformed into a decryption key by applying a hash
	 * function.
	 */
	public final byte[] patternKey;

	/**
	 * The type of query. Can only take one of the eight possible forms QQQ,
	 * RQQ, ..., RRR.
	 */
	public final int patternType;

	/**
	 * Stores the modulus.
	 */
	public final BigInteger n;

	/**
	 * Creates a new query pattern based on the given input parameters.
	 * 
	 * @param authorizationKey
	 *            The authorization key received from the data owner. It may
	 *            already encoded bound query parts defined by the data owner.
	 * @param patternType
	 *            The pattern type. Must be one of the the query types defined
	 *            in {@link PatternTypes}.
	 * @param subjectVar
	 *            States whether the subject is a queried part or a query
	 *            parameter. In the first case, the string value of this
	 *            parameter must start with the character <code>?</code>. In the
	 *            latter case, the subject must be a URI if specified by the
	 *            user. If the subject is already encoded in the query key, the
	 *            parameter may also be <code>null</code>.
	 * @param predicateVar
	 *            States whether the predicate is a queried part or a query
	 *            parameter. In the first case, the string value of this
	 *            parameter must start with the character <code>?</code>. In the
	 *            latter case, the predicate must be a URI if specified by the
	 *            user. If the predicate is already encoded in the query key,
	 *            the parameter may also be <code>null</code>.
	 * @param objectVar
	 *            States whether the object is a queried part or a query
	 *            parameter. In the first case, the string value of this
	 *            parameter must start with the character <code>?</code>. In the
	 *            latter case, the object must be a URI if specified by the
	 *            user. If the object is already encoded in the query key, the
	 *            parameter may also be <code>null</code>.
	 */
	public TriplePattern(BigInteger n, byte[] authorizationKey,
			int patternType, String subjectVar, String predicateVar,
			String objectVar) throws CryptoException {
		this.subjectVar = subjectVar;
		this.predicateVar = predicateVar;
		this.objectVar = objectVar;
		this.n = n;

		// Create a new utility object in order to combine the parts of the
		// query key.
		CombiningFunction combFunc = new CombiningFunction();

		// Integrate all user query parameters into the pattern key. Thus, the
		// pattern key can directly be transformed into a decryption key by
		// applying the hash function.
		switch (patternType) {
			case PatternTypes.UQQ:
				this.patternKey = combFunc.combineSubject(n, authorizationKey,
						subjectVar.getBytes(Constants.STRING_CHARSET));
				this.patternType = PatternTypes.RQQ;
				break;
			case PatternTypes.QUQ:
				this.patternKey = combFunc.combinePredicate(n,
						authorizationKey, predicateVar);
				this.patternType = PatternTypes.QRQ;
				break;
			case PatternTypes.QQU:
				this.patternKey = combFunc.combineObject(n, authorizationKey,
						objectVar);
				this.patternType = PatternTypes.QQR;
				break;
			case PatternTypes.RUQ:
				this.patternKey = combFunc.combinePredicate(n,
						authorizationKey, predicateVar);
				this.patternType = PatternTypes.RRQ;
				break;
			case PatternTypes.URQ:
				this.patternKey = combFunc.combineSubject(n, authorizationKey,
						subjectVar);
				this.patternType = PatternTypes.RRQ;
				break;
			case PatternTypes.UUQ:
				this.patternKey = combFunc.combineSubjectAndPredicate(n,
						authorizationKey, subjectVar, predicateVar);
				this.patternType = PatternTypes.RRQ;
				break;
			case PatternTypes.RQU:
				this.patternKey = combFunc.combineObject(n, authorizationKey,
						objectVar);
				this.patternType = PatternTypes.RQR;
				break;
			case PatternTypes.UQR:
				this.patternKey = combFunc.combineSubject(n, authorizationKey,
						subjectVar);
				this.patternType = PatternTypes.RQR;
				break;
			case PatternTypes.UQU:
				this.patternKey = combFunc.combineSubjectAndObject(n,
						authorizationKey, subjectVar, objectVar);
				this.patternType = PatternTypes.RQR;
				break;
			case PatternTypes.QRU:
				this.patternKey = combFunc.combineObject(n, authorizationKey,
						objectVar);
				this.patternType = PatternTypes.QRR;
				break;
			case PatternTypes.QUR:
				this.patternKey = combFunc.combinePredicate(n,
						authorizationKey, predicateVar);
				this.patternType = PatternTypes.QRR;
				break;
			case PatternTypes.QUU:
				this.patternKey = combFunc.combinePredicateAndObject(n,
						authorizationKey, predicateVar, objectVar);
				this.patternType = PatternTypes.QRR;
				break;
			case PatternTypes.RRU:
				this.patternKey = combFunc.combineObject(n, authorizationKey,
						objectVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.RUR:
				this.patternKey = combFunc.combinePredicate(n,
						authorizationKey, predicateVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.URR:
				this.patternKey = combFunc.combineSubject(n, authorizationKey,
						subjectVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.RUU:
				this.patternKey = combFunc.combinePredicateAndObject(n,
						authorizationKey, predicateVar, objectVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.URU:
				this.patternKey = combFunc.combineSubjectAndObject(n,
						authorizationKey, subjectVar, objectVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.UUR:
				this.patternKey = combFunc.combineSubjectAndPredicate(n,
						authorizationKey, subjectVar, predicateVar);
				this.patternType = PatternTypes.RRR;
				break;
			case PatternTypes.UUU:
				this.patternKey = combFunc.combineAll(n, authorizationKey,
						subjectVar, predicateVar, objectVar);
				this.patternType = PatternTypes.RRR;
				break;
			// In all other cases, the query parameters are already encoded into
			// the query key. This corresponds to one of the eight query types
			// QQQ, RQQ, ..., RRR.
			default:
				this.patternKey = combFunc.combineNone(n, authorizationKey);
				this.patternType = patternType;
		}
	}

	@Override
	public String toString() {

		String type;

		switch (this.patternType) {
			case PatternTypes.RRR:
				type = "PPP";
				break;
			case PatternTypes.QRR:
				type = "MPP";
				break;
			case PatternTypes.RQR:
				type = "PMP";
				break;
			case PatternTypes.RRQ:
				type = "PPM";
				break;
			case PatternTypes.QQR:
				type = "MMP";
				break;
			case PatternTypes.QRQ:
				type = "MPM";
				break;
			case PatternTypes.RQQ:
				type = "PMM";
				break;
			case PatternTypes.QQQ:
				type = "MMM";
				break;
			default:
				type = "---";
		}

		return "[" + type + "] " + this.subjectVar + " " + this.predicateVar
				+ " " + this.objectVar + " (" + new BigInteger(this.patternKey)
				+ ")";
	}

}
