package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

public class CryptoException extends Exception {

	/**
	 * The serial version ID.
	 */
	private static final long serialVersionUID = -4783744337656048403L;

	public CryptoException() {
	}
	
	public CryptoException(String message) {
		super(message);
	}
	
	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public CryptoException(Throwable cause) {
		super(cause);
	}
}
