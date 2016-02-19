package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;

public class Graph {

	public Map<Integer, byte[]> ciphertexts;

	public Graph() {
		this.ciphertexts = new HashMap<Integer, byte[]>();
	}

	public static Graph loadGraph(String fileName) throws IOException {
		return loadGraph(new File(fileName));
	}

	public static Graph loadGraph(File graphFile) throws IOException {

		Graph graph = new Graph();

		BufferedInputStream streamReader = new BufferedInputStream(
				new FileInputStream(graphFile));

		// Format for writing the triples:
		// indexKey - ciphertext size - ciphertext
		// 4 bytes - 4 bytes <ciphertext size> bytes

		// Read as long as there are at least 8 bytes left. These bytes result
		// from the two integers.
		while (streamReader.available() > 8) {

			// Read the id of the ciphertext.
			byte[] idArray = new byte[4];
			streamReader.read(idArray);

			// Read the size of the ciphertext.
			byte[] lengthArray = new byte[4];
			streamReader.read(lengthArray);

			// read the ciphertext.
			byte[] ciphertext = new byte[Utils.byteArrayToInt(lengthArray)];
			streamReader.read(ciphertext);

			// Add the ciphertext to the HashMap.
			graph.ciphertexts.put(Utils.byteArrayToInt(idArray), ciphertext);
		}

		streamReader.close();

		return graph;
	}

	public void writeToFile(String fileName) throws IOException {
		writeToFile(new File(fileName));
	}

	public void writeToFile(File outputFile) throws IOException {

		BufferedOutputStream streamWriter = new BufferedOutputStream(
				new FileOutputStream(outputFile));

		// Format for writing the triples:
		// indexKey - ciphertext size - ciphertext
		// 4 bytes - 4 bytes <ciphertext size> bytes
		for (int i : this.ciphertexts.keySet()) {

			// Write the indexKey.
			streamWriter.write(Utils.intToByteArray(i));

			// Get the next ciphertext.
			byte[] value = this.ciphertexts.get(i);

			// Write the size of the ciphertext.
			streamWriter.write(Utils.intToByteArray(value.length));

			// Write the actual ciphertext.
			streamWriter.write(value);
		}

		streamWriter.close();
	}

	public void addCiphertext(Integer cID, byte[] ciphertext) {
		this.ciphertexts.put(cID, ciphertext);
	}

	public void addCiphertext(int cID, byte[] ciphertext) {
		this.ciphertexts.put(cID, ciphertext);
	}

	public byte[] getCiphertext(int cID) {
		return this.ciphertexts.get(cID);
	}

	public byte[] getCiphertext(Integer cID) {
		return this.ciphertexts.get(cID);
	}

	public Collection<byte[]> getCiphertexts(Iterable<Integer> cIDSet) {
		Collection<byte[]> result = new LinkedList<byte[]>();

		for (int cID : cIDSet)
			result.add(this.ciphertexts.get(cID));

		return result;
	}

}
