package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto;

import java.security.MessageDigest;

import javax.crypto.Cipher;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;

public abstract class CryptoBase {

	protected MessageDigest digester;
	protected CombiningFunction combFunc;

	protected Cipher cipher;
	protected byte[] iv;

	protected CryptoBase(byte[] iv) throws CryptoException {
		try {
			this.iv = iv;
			this.digester = MessageDigest
					.getInstance(Constants.HASH_ALGORITHM);
			this.cipher = Cipher.getInstance(Constants.CRYPTO_ALGORITHM);
			this.combFunc = new CombiningFunction();
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}
	
	public byte[] getIv() {
		return this.iv;
	}

}
