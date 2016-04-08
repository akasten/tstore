package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common;

public class QueriedDocument {

	private final String plainTextFileName;

	private final String encryptedFileName;

	private final String indexFileName;

	private final String encryptedIndexedFileName;

	public QueriedDocument(String plainTestFileName, String encryptedFileName,
			String encryptedIndexedFileName, String indexFileName) {
		this.plainTextFileName = plainTestFileName;
		this.encryptedFileName = encryptedFileName;
		this.encryptedIndexedFileName = encryptedIndexedFileName;
		this.indexFileName = indexFileName;
	}

	public String getPlainTextFileName() {
		return plainTextFileName;
	}

	public String getEncryptedFileName() {
		return encryptedFileName;
	}

	public String getEncryptedIndexedFileName() {
		return this.encryptedIndexedFileName;
	}

	public String getIndexFileName() {
		return this.indexFileName;
	}

}
