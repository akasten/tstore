package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.BasicTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;

/**
 * Used for creating random ciphertext identifiers as done in step 4.
 * 
 * @author Andreas Kasten
 * 
 */
public class IdentifierSet {

	/**
	 * An array storing all created identifiers.
	 */
	private int[] ids;

	/**
	 * Stores the position of the next identifier to be returned.
	 */
	private int currentPos;

	/**
	 * Creates a new identifier set consisting of 8 x <code>tripleCount</code>
	 * different identifiers. The identifiers in the set are shuffled.
	 * 
	 * @param tripleCount
	 *            The number of triples for which the identifiers shall be
	 *            created.
	 */
	public IdentifierSet(int tripleCount) {
		// Set the position of the next identifier to 0.
		this.currentPos = 0;

		// Initialize the array for storing the identifiers. As each triple is
		// encrypted as eight different ciphertexts, the number of identifiers
		// is eight times larger than the number of triples.
		this.ids = new int[tripleCount * BasicTypes.TYPE_COUNT];

		// Create the initial ordering of identifers.
		for (int i = 0; i < tripleCount * BasicTypes.TYPE_COUNT; ++i) {
			// Please note that 0 is not used as identifier.
			ids[i] = i + 1;
		}

		// Shuffle the identifiers in place.
		Utils.shuffleArray(ids);
	}

	/**
	 * Returns the next random identifier. Does not perform any checks if there
	 * really is such an identifier.
	 * 
	 * @return The next random identifier stored in the internal array.
	 * @throws ArrayIndexOutOfBoundsException
	 *             Will be thrown of the method is called even if there are no
	 *             more identifiers left.
	 */
	public int getNextId() {
		// Return the next identifier and update the position of the next
		// identifier.
		return this.ids[this.currentPos++];
	}

	/**
	 * Checks whether or not there are more identifiers.
	 * 
	 * @return <code>true</code> if there are more identifiers left and
	 *         <code>false</code> otherwise.
	 */
	public boolean hasNextId() {
		return this.currentPos < this.ids.length;
	}

}
