package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.crypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;

import org.apache.commons.io.IOUtils;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.crypto.FileEncrypter;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.Evaluatable;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.common.QueriedDocument;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.ByteArrayTripleReader;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.TripleReader;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.query.ComplexFileQuerier;

public class CryptoStore extends Evaluatable<CryptoQuery> {

	private FileEncrypter encrypter;

	private ComplexFileQuerier querier;

	private TripleReader tripleReader;

	public CryptoStore(QueriedDocument document) {
		super(document);
		this.encrypter = new FileEncrypter();
		this.querier = new ComplexFileQuerier();
	}

	@Override
	public boolean loadDocument(byte[] iv) {
		try {
			ByteArrayInputStream inOut = new ByteArrayInputStream(
					IOUtils.toByteArray(new FileInputStream(new File(document
							.getEncryptedFileName()))));

			this.tripleReader = new ByteArrayTripleReader(inOut);

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv) {
		try {
			this.encrypter.encryptFile(n, basicKeys, iv,
					document.getPlainTextFileName(),
					document.getEncryptedFileName());

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean performQuery(CryptoQuery query) {
		try {
			this.querier.performQuery(query.getN(), query.getQueryPatterns(),
					this.tripleReader, query.getIv());

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
