package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.io;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.Utils;

public class IndexedFileTripleReader {

	private BufferedInputStream streamReader;

	public IndexedFileTripleReader(InputStream in) {
		this.streamReader = new BufferedInputStream(in);
	}

	public IndexedFileTripleReader(String fileName)
			throws FileNotFoundException {
		this.streamReader = new BufferedInputStream(new FileInputStream(
				fileName));
	}

	/**
	 * Reads all encrypted triples from a file. The eight ciphertexts of a
	 * triple are associated with different integer identifiers.
	 * 
	 * @return A Map containing all ciphertexts of all triples. The ciphertexts
	 *         are identified by integers.
	 * @throws IOException
	 *             Is thrown of the file cannot be read.
	 */
	public Map<Integer, byte[]> readTriples() throws IOException {

		Map<Integer, byte[]> result = new HashMap<Integer, byte[]>();

		// Format for writing the triples:
		// indexKey - ciphertext size - ciphertext
		// 4 bytes - 4 bytes <ciphertext size> bytes

		// Read as long as there are at least 8 bytes left. These bytes result
		// from the two integers.
		while (this.streamReader.available() > 8) {

			// Read the id of the ciphertext.
			byte[] idArray = new byte[4];
			this.streamReader.read(idArray);

			// Read the size of the ciphertext.
			byte[] lengthArray = new byte[4];
			this.streamReader.read(lengthArray);

			// read the ciphertext.
			byte[] ciphertext = new byte[Utils.byteArrayToInt(lengthArray)];
			this.streamReader.read(ciphertext);

			// Add the ciphertext to the HashMap.
			result.put(Utils.byteArrayToInt(idArray), ciphertext);
		}

		return result;
	}

	public void close() throws IOException {
		this.streamReader.close();
	}
}
