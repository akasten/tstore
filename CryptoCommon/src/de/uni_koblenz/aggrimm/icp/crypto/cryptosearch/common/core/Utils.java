package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Random;

public class Utils {

	public static String byteArrayToString(byte[] byteArray) {
		String res = "";
		for (byte b : byteArray)
			res += b + " ";
		return res.substring(0, res.length() - 1);
	}

	public static int bytesToInt(byte b1, byte b2, byte b3, byte b4) {
		return ((b1 & 0x000000FF) << 24) + ((b2 & 0x000000FF) << 16)
				+ ((b3 & 0x000000FF) << 8) + (b4 & 0x000000FF);
	}

	public static int byteArrayToInt(byte[] byteArray) {
		return ((byteArray[0] & 0x000000FF) << 24)
				+ ((byteArray[1] & 0x000000FF) << 16)
				+ ((byteArray[2] & 0x000000FF) << 8)
				+ (byteArray[3] & 0x000000FF);
	}

	public static byte[] intToByteArray(int i) {
		return new byte[] { (byte) (i >>> 24), (byte) (i >>> 16),
				(byte) (i >>> 8), (byte) i };
	}

	public static byte booleanToByte(boolean b) {
		return b ? (byte) 1 : 0;
	}

	public static boolean byteToBoolean(byte b) {
		return (b == 1) ? true : false;
	}

	/**
	 * Shuffles an integer array in place. The source code is taken from
	 * <a>http:
	 * //stackoverflow.com/questions/1519736/random-shuffling-of-an-array</a>.
	 * 
	 * @param array
	 *            The array to be shuffled in place.
	 */
	public static void shuffleArray(int[] array) {
		int index, tmp;
		Random random = new Random(System.currentTimeMillis());

		for (int i = array.length - 1; i > 0; --i) {
			index = random.nextInt(i + 1);
			tmp = array[index];
			array[index] = array[i];
			array[i] = tmp;
		}
	}

	/**
	 * Counts the number of triples in a file containing an N-Triples
	 * representation of a graph.
	 * 
	 * @param fileName
	 *            The file name of the serialized graph.
	 * @return The number of triples in the graph.
	 * @throws IOException
	 *             Is thrown if the file cannot be read properly.
	 */
	public static int countTriples(String fileName) throws IOException {
		return countTriples(new File(fileName));
	}

	/**
	 * Counts the number of triples in a file containing an N-Triples
	 * representation of a graph.
	 * 
	 * @param file
	 *            The file containing the serialized graph.
	 * @return The number of triples in the graph.
	 * @throws IOException
	 *             Is thrown if the file cannot be read properly.
	 */
	public static int countTriples(File file) throws IOException {
		FileInputStream is = new FileInputStream(file);
		BufferedReader reader = new BufferedReader(new InputStreamReader(is));

		int lines = 0;
		String s = reader.readLine();
		while (s != null) {
			if (!s.startsWith("#") && !s.isEmpty() && s.endsWith("."))
				++lines;
			s = reader.readLine();
		}

		is.close();
		return lines;
	}

}
