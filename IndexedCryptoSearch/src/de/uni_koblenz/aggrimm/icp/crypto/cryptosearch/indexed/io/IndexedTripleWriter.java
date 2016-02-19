package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.io;

import java.io.IOException;
import java.util.Map;

public interface IndexedTripleWriter {

	public abstract void writeTriples(Map<Integer, byte[]> triples)
			throws IOException;

	public abstract void writeTriple(int[] tripleIds, byte[][] triple)
			throws IOException;

	public abstract void writeTriple(int mmmId, int mmpId, int mpmId,
			int pmmId, int ppmId, int pmpId, int mppId, int pppId, byte[] mmmE,
			byte[] mmpE, byte[] mpmE, byte[] pmmE, byte[] ppmE, byte[] pmpE,
			byte[] mppE, byte[] pppE) throws IOException;

	public abstract void close() throws IOException;

}
