package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.Iterator;

import org.semanticweb.yars.nx.Node;
import org.semanticweb.yars.nx.file.NxGzInput;
import org.semanticweb.yars.nx.parser.NxParser;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.BasicTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.TripleEncrypter;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io.FileTripleWriter;

public class FileEncrypter {

	public void encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv,
			String plaintextFile, String encryptedFile) throws CryptoException {
		encryptFile(n, basicKeys, iv, new File(plaintextFile), new File(
				encryptedFile));
	}

	public void encryptFile(BigInteger n, byte[][] basicKeys, byte[] iv,
			File plaintextFile, File encryptedFile) throws CryptoException {
		try {
			Iterator<Node[]> parser;

			// TODO: Since the following test for checking the file type is not
			// really reliable, it should be replaced by a better one.
			if (plaintextFile.getName().endsWith(".gz"))
				parser = new NxGzInput(plaintextFile);
			else
				parser = new NxParser(new FileInputStream(plaintextFile));

			FileTripleWriter writer = new FileTripleWriter(
					new FileOutputStream(encryptedFile));
			TripleEncrypter encrypter = new TripleEncrypter(iv);

			while (parser.hasNext()) {
				try {
					Node[] node = parser.next();

					byte[] subject = node[0].toString().getBytes(
							Constants.STRING_CHARSET);
					byte[] predicate = node[1].toString().getBytes(
							Constants.STRING_CHARSET);
					byte[] object = node[2].toString().getBytes(
							Constants.STRING_CHARSET);

					byte[] mmmE = encrypter.encryptMMM(n,
							basicKeys[BasicTypes.MMM], subject, predicate,
							object)[0];
					byte[] mmpE = encrypter.encryptMMP(n,
							basicKeys[BasicTypes.MMP], subject, predicate,
							object)[0];
					byte[] mpmE = encrypter.encryptMPM(n,
							basicKeys[BasicTypes.MPM], subject, predicate,
							object)[0];
					byte[] pmmE = encrypter.encryptPMM(n,
							basicKeys[BasicTypes.PMM], subject, predicate,
							object)[0];
					byte[] ppmE = encrypter.encryptPPM(n,
							basicKeys[BasicTypes.PPM], subject, predicate,
							object)[0];
					byte[] pmpE = encrypter.encryptPMP(n,
							basicKeys[BasicTypes.PMP], subject, predicate,
							object)[0];
					byte[] mppE = encrypter.encryptMPP(n,
							basicKeys[BasicTypes.MPP], subject, predicate,
							object)[0];
					byte[] pppE = encrypter.encryptPPP(n,
							basicKeys[BasicTypes.PPP], subject, predicate,
							object)[0];

					writer.writeTriple(mmmE, mmpE, mpmE, pmmE, ppmE, pmpE,
							mppE, pppE);
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}

			writer.close();
		}
		catch (CryptoException e) {
			throw e;
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}

}
