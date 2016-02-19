package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.io;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.Utils;

public class IndexedFileTripleWriter implements IndexedTripleWriter {

	private BufferedOutputStream streamWriter;

	public IndexedFileTripleWriter(OutputStream out) {
		this.streamWriter = new BufferedOutputStream(out);
	}

	@Override
	public void writeTriples(Map<Integer, byte[]> triples) throws IOException {

		// Format for writing the triples:
		// indexKey - ciphertext size - ciphertext
		// 4 bytes  - 4 bytes           <ciphertext size> bytes
		for (int i : triples.keySet()) {
			
			// Write the indexKey.
			this.streamWriter.write(Utils.intToByteArray(i));
			
			// Get the next ciphertext.
			byte[] value = triples.get(i);
			
			// Write the size of the ciphertext.
			this.streamWriter.write(Utils.intToByteArray(value.length));
			
			// Write the actual ciphertext.
			this.streamWriter.write(value);
		}
	}
	
	public void writeTriple(int tripleId, byte[] triple) throws IOException {
		
		// Format for writing the triples:
		// indexKey - ciphertext size - ciphertext
		// 4 bytes  - 4 bytes           <ciphertext size> bytes
		this.streamWriter.write(Utils.intToByteArray(tripleId));
		this.streamWriter.write(Utils.intToByteArray(triple.length));
		this.streamWriter.write(triple);
	}

	@Override
	public void writeTriple(int[] tripleIds, byte[][] triple)
			throws IOException {

		for (int i = 0; i < tripleIds.length; ++i) {
			writeTriple(tripleIds[i], triple[i]);
		}
	}

	@Override
	public void writeTriple(int mmmId, int mmpId, int mpmId, int pmmId,
			int ppmId, int pmpId, int mppId, int pppId, byte[] mmmE,
			byte[] mmpE, byte[] mpmE, byte[] pmmE, byte[] ppmE, byte[] pmpE,
			byte[] mppE, byte[] pppE) throws IOException {

		writeTriple(new int[] { mmmId, mmpId, mpmId, pmmId, ppmId, pmpId,
				mppId, pppId }, new byte[][] { mmmE, mmpE, mpmE, pmmE, ppmE,
				pmpE, mppE, pppE });
	}

	@Override
	public void close() throws IOException {
		streamWriter.close();
	}

}
