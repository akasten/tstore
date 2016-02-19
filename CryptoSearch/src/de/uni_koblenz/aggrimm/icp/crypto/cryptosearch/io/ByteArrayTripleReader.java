package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.NoSuchElementException;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;

public class ByteArrayTripleReader implements TripleReader {

	private ByteArrayInputStream buffer;

	public ByteArrayTripleReader(byte[] in) {
		this.buffer = new ByteArrayInputStream(in);
		this.buffer.mark(0);
	}

	public ByteArrayTripleReader(ByteArrayInputStream in) {
		this.buffer = in;
		this.buffer.mark(0);
	}

	@Override
	public byte[][] readTriple() throws IOException {

		byte[] tmp = new byte[4];
		this.buffer.read(tmp);

		byte[][] result = new byte[8][];

		for (int i = 0; i < 8; ++i) {
			this.buffer.read(tmp);
			byte[] part = new byte[Utils.byteArrayToInt(tmp)];
			this.buffer.read(part);

			result[i] = part;
		}

		return result;
	}

	@Override
	public void skipTriple() throws IOException {
		readTriple();
	}

	@Override
	public void close() throws IOException {
		this.buffer.reset();
		this.buffer.mark(0);
	}

	@Override
	public boolean hasNext() {
		return this.buffer.available() > 36;
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
