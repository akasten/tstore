package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io;

import java.io.IOException;
import java.util.Iterator;

public interface TripleReader extends Iterator<byte[][]> {

	public abstract byte[][] readTriple() throws IOException;

	public abstract void skipTriple() throws IOException;

	public abstract void close() throws IOException;

}
