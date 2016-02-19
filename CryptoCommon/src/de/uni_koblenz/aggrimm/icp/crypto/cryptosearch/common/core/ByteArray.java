package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core;

/**
 * This class provides a wrapper for byte arrays. The class allows it to use
 * byte arrays as keys in a {@link java.util.HashMap}. This is done by
 * implementing the methods {@link #compareTo(ByteArray)},
 * {@link #equals(Object)}, and {@link #hashCode()}.
 * 
 * @author Andreas Kasten
 * 
 */
public final class ByteArray implements Comparable<ByteArray> {

	/**
	 * The byte array to be wrapped.
	 */
	private byte[] array;

	/**
	 * Creates a new instance of the class <code>ByteArray</code> which wraps
	 * the given byte array.
	 * 
	 * @param array
	 *            The byte array to be wrapped.
	 */
	public ByteArray(byte[] array) {
		this.array = array;
	}

	/**
	 * Returns the internal byte array.
	 * 
	 * @return The wrapped byte array.
	 */
	public byte[] getArray() {
		return this.array;
	}

	/**
	 * Returns the length of the wrapped array.
	 * 
	 * @return The length of the wrapped array
	 */
	public int length() {
		return this.array.length;
	}

	@Override
	public boolean equals(Object obj) {

		// If both objects are completely identical, return true.
		if (this == obj)
			return true;

		// If the other object is not a ByteArray, it cannot be the same as the
		// current object.
		if (!(obj instanceof ByteArray))
			return false;

		ByteArray that = (ByteArray) obj;

		// If both arrays have different lengths, they cannot store the same
		// values.
		if (this.array.length != that.array.length)
			return false;

		// Both objects are identical if they store the same values in the same
		// order. Otherwise, they are different.
		for (int i = 0; i < this.array.length; ++i) {
			if (this.array[i] != that.array[i])
				return false;
		}
		return true;
	}

	@Override
	public int hashCode() {

		/**
		 * Simplified form of
		 * <url>http://docs.oracle.com/javase/6/docs/api/java/
		 * util/List.html#hashCode%28%29</url>
		 */
		int hashCode = 1;
		for (byte b : this.array)
			hashCode = 31 * hashCode + b;

		return hashCode;
	}

	@Override
	public int compareTo(ByteArray that) {

		// First, compare the lengths of the arrays.
		if (this.array.length > that.array.length)
			return 1;
		else if (this.array.length < that.array.length)
			return -1;

		// Compare the actual values for arrays of equal length.
		for (int i = 0; i < this.array.length; ++i) {
			if (this.array[i] > that.array[i])
				return 1;
			else if (this.array[i] < that.array[i])
				return -1;
		}

		// The objects are equal if both arrays store the same values in the
		// same order.
		return 0;
	}

	@Override
	public String toString() {
		String res = "";
		
		for(byte b : this.array)
			res += b + " ";
		
		return res;
	}

}
