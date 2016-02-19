package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;

public class FileTripleWriter implements TripleWriter {

	private BufferedOutputStream streamWriter;

	public FileTripleWriter(OutputStream out) {
		this.streamWriter = new BufferedOutputStream(out);
	}

	public FileTripleWriter(String fileName) throws FileNotFoundException {
		this.streamWriter = new BufferedOutputStream(new FileOutputStream(
				fileName));
	}

	// length: 4 4 l(mmm) 4 l(mmp) ... 4 l(ppp)
	// content: totalLength l(mmm) mmm l(mmp) mmp ... l(ppp) ppp

	@Override
	public void writeTriple(byte[][] triple) throws IOException {

		// 4 = number of bytes for storing an integer, i.e. Integer.SIZE / 8
		// 8 = triple.length (each corresponds to one integer)
		// => 8 * 4 = 32
		int totalLength = 32;

		for (byte[] b : triple) {
			totalLength += b.length;
		}

		this.streamWriter.write(Utils.intToByteArray(totalLength));

		for (byte[] b : triple) {
			this.streamWriter.write(Utils.intToByteArray(b.length));
			this.streamWriter.write(b);
		}
	}

	@Override
	public void writeTriple(byte[] mmmE, byte[] mmpE, byte[] mpmE, byte[] pmmE,
			byte[] ppmE, byte[] pmpE, byte[] mppE, byte[] pppE)
			throws IOException {

		writeTriple(new byte[][] { mmmE, mmpE, mpmE, pmmE, ppmE, pmpE, mppE,
				pppE });
	}

	@Override
	public void close() throws IOException {
		this.streamWriter.close();
	}

}
