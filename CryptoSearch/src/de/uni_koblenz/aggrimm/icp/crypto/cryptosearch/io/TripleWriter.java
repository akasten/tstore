package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io;

import java.io.IOException;

public interface TripleWriter {

	public abstract void writeTriple(byte[][] triple) throws IOException;

	public abstract void writeTriple(byte[] mmmE, byte[] mmpE, byte[] mpmE,
			byte[] pmmE, byte[] ppmE, byte[] pmpE, byte[] mppE, byte[] pppE)
			throws IOException;

	public abstract void close() throws IOException;

}
