package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;

public class FileTripleReader implements TripleReader {

	private BufferedInputStream streamReader;

	public FileTripleReader(InputStream in) {
		this.streamReader = new BufferedInputStream(in);
	}

	public FileTripleReader(String fileName) throws FileNotFoundException {
		this.streamReader = new BufferedInputStream(new FileInputStream(
				fileName));
	}

	@Override
	public byte[][] readTriple() throws IOException {

		// Read the overall size of the encrypted triple.
		byte[] tmp = new byte[4];
		this.streamReader.read(tmp);

		byte[][] result = new byte[8][];

		for (int i = 0; i < 8; ++i) {
			this.streamReader.read(tmp);
			byte[] part = new byte[Utils.byteArrayToInt(tmp)];
			this.streamReader.read(part);

			result[i] = part;
		}

		return result;
	}

	@Override
	public void skipTriple() throws IOException {
		byte[] tmp = new byte[4];
		this.streamReader.read(tmp);
		this.streamReader.skip(Utils.byteArrayToInt(tmp));
	}

	@Override
	public void close() throws IOException {
		this.streamReader.close();
	}

	@Override
	public boolean hasNext() {
		try {
			return this.streamReader.available() > 36;
		}
		catch (IOException e) {
			return false;
		}
	}

	@Override
	public byte[][] next() {
		try {
			return this.readTriple();
		}
		catch (IOException e) {
			throw new NoSuchElementException();
		}
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException("Operation not supported.");
	}

}
