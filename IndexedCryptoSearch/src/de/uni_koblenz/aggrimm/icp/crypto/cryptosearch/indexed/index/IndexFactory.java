package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.semanticweb.yars.nx.Node;
import org.semanticweb.yars.nx.file.NxGzInput;
import org.semanticweb.yars.nx.parser.NxParser;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.BasicTypes;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.ByteArray;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoBase;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.TripleEncrypter;

/**
 * 
 * 
 * @author Andreas Kasten
 * 
 */
public class IndexFactory extends CryptoBase {

	/**
	 * Associates an encryption key with a set of ciphertext identifies. The
	 * ciphertexts of each set are encrypted with the same encryption key.
	 */
	private Map<ByteArray, Set<Integer>> ciphertextSets;

	/**
	 * Initializes the set of local members.
	 * 
	 * @param iv
	 *            The initialization vector used for encrypting the index'
	 *            contents.
	 */
	public IndexFactory(byte[] iv) throws CryptoException {
		super(iv);

		init();
	}

	private void init() {
		this.ciphertextSets = new HashMap<ByteArray, Set<Integer>>();
	}

	/**
	 * Adds a new ciphertext id to the set which is identified by the given
	 * encryption key. This method is used for grouping all ciphertext ids
	 * according to their encryption key as it is done in step 5.
	 * 
	 * @param encryptionKey
	 *            The key identifying the set of ciphertext ids.
	 * @param ciphertextId
	 *            The ciphertext id to be added to the set.
	 */
	private void addCiphertextId(byte[] encryptionKey, int ciphertextId) {

		// Wrap the byte array to an instance of the class ByteArray.
		ByteArray encArray = new ByteArray(encryptionKey);

		// Try to retrieve the set of ciphertext ids for the given encryption
		// key. The set may be null if it was not created yet.
		Set<Integer> idSet = this.ciphertextSets.get(encArray);

		// If the set of ciphertext ids was not created yet, create it now and
		// add it to the set of all ciphertext sets.
		if (idSet == null) {
			idSet = new HashSet<Integer>();
			this.ciphertextSets.put(encArray, idSet);
		}

		// Add the new ciphertext id to the set.
		idSet.add(ciphertextId);
	}

	/**
	 * Creates the index tree based on the sets of ciphertext ids.
	 * 
	 * @return The index tree created from the previously added ciphertext ids.
	 */
	private IndexTree createIndexTree() throws CryptoException {
		
//		// TODO /////////////////////////////////////
//		long avg = 0;
//		long min = Long.MAX_VALUE;
//		long max = Long.MIN_VALUE;
//		for (ByteArray encKey : this.ciphertextSets.keySet()) {
//			int size = this.ciphertextSets.get(encKey).size();
//			
//			avg +=size;
//			if (size < min)
//				min = size;
//			if (size > max)
//				max = size;
//		}
//		
//		
//		System.out.println("Possible queries: " + this.ciphertextSets.keySet().size());
//		System.out.println("Average query size: " + avg );
//		System.out.println("Min query size: " + min );
//		System.out.println("Max query size: " + max );
//		System.out.println("FIN!!!!");
//		// TODO /////////////////////////////////////
		

		// Initialize the index tree.
		Map<ByteArray, byte[]> indexTree = new TreeMap<ByteArray, byte[]>();

		// Iterate over all encryption keys and their respective sets of
		// ciphertext ids.
		for (ByteArray encKey : this.ciphertextSets.keySet()) {

			// Store the reference to the array in an additional variable.
			byte[] encArray = encKey.getArray();

			// Stores the current position of the array.
			int arrayPos = 0;
			int[] array = new int[Constants.ARRAY_SIZE];

			// Stores the count of the arrays per set. There is at least one
			// array.
			int arrayCount = 1;

			// Iterate over all ciphertext identifiers stored in the set.
			Iterator<Integer> setIter = this.ciphertextSets.get(encKey)
					.iterator();
			while (setIter.hasNext()) {

				// Get the next ciphertext id from the set.
				int id = setIter.next();

				// Store this ciphertext id in the array and increment the
				// current position of the array.
				array[arrayPos++] = id;

				// If the current array is full, add it to the index tree and
				// create another array.
				if (arrayPos >= Constants.ARRAY_SIZE) {

					// System.out.println(encKey);
					// System.out.println("hasNext: " + setIter.hasNext());

					// Store the complete array in the index tree.
					storeArray(indexTree, encArray, array, arrayCount,
							setIter.hasNext());
					arrayCount++;

					// Create a new array since the current array is already
					// full. Also, reset the array position.
					array = new int[Constants.ARRAY_SIZE];
					arrayPos = 0;
				}
			}

			// If the last array contains at least one entry, store it in the
			// index tree as well.
			if (arrayPos != 0)
				storeArray(indexTree, encArray, array, arrayCount,
						setIter.hasNext());
		}

		return new IndexTree(indexTree, this.iv);
	}

	/**
	 * Stores the given array in the given indexTree. The key for this array is
	 * a combination of the given <code>encArray</code> and the
	 * <code>arrayCount</code>.
	 * 
	 * @param indexTree
	 *            The Map into which the new array shall be stored.
	 * @param encryptionKey
	 *            The encryption key used for encryption the array. The key is
	 *            also used for creating the array's index key.
	 * @param array
	 *            The array to be stored in the index tree.
	 * @param arrayId
	 *            The local identifier of the array. This identifier is used to
	 *            distinguish between different arrays of the same set.
	 * @param hasNext
	 *            States whether or not the current array is the last array of
	 *            its set.
	 */
	private void storeArray(Map<ByteArray, byte[]> indexTree,
			byte[] encryptionKey, int[] array, int arrayId, boolean hasNext) {

		// Transform the current array id to a byte array and increment the id.
		// The number 4 results from idArray.length.
		byte[] idArray = Utils.intToByteArray(arrayId);
		byte[] indexKey = new byte[encryptionKey.length + 4];

		// Create the index key. This key consists of the encryption
		// key and the array id. In order to do this, copy the byte
		// array representations of the encryption key and the array
		// id to a new byte array. This byte array corresponds to
		// the index key.
		// The number 4 results from idArray.length.
		System.arraycopy(encryptionKey, 0, indexKey, 0, encryptionKey.length);
		System.arraycopy(idArray, 0, indexKey, encryptionKey.length, 4);

		// Encrypt the array together with its hasNext marker.
		byte[] ciphertext = encryptArray(encryptionKey, hasNext ? (byte) 1 : 0,
				array);

		// Add the new array to the index tree. Make sure to use a digest of the
		// index key instead of the index key itself.
		indexTree
				.put(new ByteArray(this.digester.digest(indexKey)), ciphertext);
	}

	/**
	 * Encrypts an integer array together with an additional information about
	 * whether or not this array is the last array of its set. This information
	 * is stored as a byte which precedes the actual integer array. The
	 * encryption is done using the given encryption key.
	 * 
	 * @param encryptionKey
	 *            Encryption key used for encrypting the array.
	 * @param isLastArray
	 *            Marks whether or not the current array is the last one of its
	 *            set. This value is encrypted together with the actual array.
	 * @param array
	 *            The array to be encrypted.
	 * @return The encrypted result.
	 */
	private byte[] encryptArray(byte[] encryptionKey, byte isLastArray,
			int[] array) {
		try {
			// Initialize the encryption stuff.
			this.cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(
					encryptionKey, 0, Constants.SECRET_KEY_SPEC_LENGTH,
					Constants.KEY_ALGORITHM), new IvParameterSpec(this.iv));

			// Used for storing the encrypted bytes.
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			// Add the isLastArray marker.
			outputStream.write(this.cipher.update(new byte[] { isLastArray }));

			// Encrypt all data parts and separate them with a corresponding
			// marker.
			for (int i : array)
				outputStream.write(this.cipher.update(Utils.intToByteArray(i)));

			// Add own padding.
			outputStream.write(this.cipher.update(Constants.PADDING, 0,
					Constants.ARRAY_PADDING));

			// Finalize the encryption.
			outputStream.write(this.cipher.doFinal());
			outputStream.close();

			return outputStream.toByteArray();
		}
		catch (Exception e) {
			// TODO: remove
			e.printStackTrace();
			return null;
		}
	}

	public IndexedGraph encryptPlaintextGraph(BigInteger n, byte[][] basicKeys,
			String plaintextFileName) throws CryptoException {
		return encryptPlaintextGraph(n, basicKeys, new File(plaintextFileName));
	}

	public IndexedGraph encryptPlaintextGraph(BigInteger n, byte[][] basicKeys,
			File plaintextFile) throws CryptoException {
		try {
			Iterator<Node[]> parser;

			// TODO: Since the following test for checking the file type is not
			// really reliable, it should be replaced by a better one.
			if (plaintextFile.getName().endsWith(".gz"))
				parser = new NxGzInput(plaintextFile);
			else
				parser = new NxParser(new FileInputStream(plaintextFile));

			IdentifierSet idSet = new IdentifierSet(
					Utils.countTriples(plaintextFile));

			TripleEncrypter encrypter = new TripleEncrypter(this.iv);
			Graph graph = new Graph();

			while (parser.hasNext()) {
				try {
					Node[] node = parser.next();

					byte[] subject = node[0].toString().getBytes(
							Constants.STRING_CHARSET);
					byte[] predicate = node[1].toString().getBytes(
							Constants.STRING_CHARSET);
					byte[] object = node[2].toString().getBytes(
							Constants.STRING_CHARSET);

					byte[][] mmmE = encrypter.encryptMMM(n,
							basicKeys[BasicTypes.MMM], subject, predicate,
							object);
					int mmmId = idSet.getNextId();
					this.addCiphertextId(mmmE[1], mmmId);
					graph.addCiphertext(mmmId, mmmE[0]);

					byte[][] mmpE = encrypter.encryptMMP(n,
							basicKeys[BasicTypes.MMP], subject, predicate,
							object);
					int mmpId = idSet.getNextId();
					this.addCiphertextId(mmpE[1], mmpId);
					graph.addCiphertext(mmpId, mmpE[0]);

					byte[][] mpmE = encrypter.encryptMPM(n,
							basicKeys[BasicTypes.MPM], subject, predicate,
							object);
					int mpmId = idSet.getNextId();
					this.addCiphertextId(mpmE[1], mpmId);
					graph.addCiphertext(mpmId, mpmE[0]);

					byte[][] pmmE = encrypter.encryptPMM(n,
							basicKeys[BasicTypes.PMM], subject, predicate,
							object);
					int pmmId = idSet.getNextId();
					this.addCiphertextId(pmmE[1], pmmId);
					graph.addCiphertext(pmmId, pmmE[0]);

					byte[][] ppmE = encrypter.encryptPPM(n,
							basicKeys[BasicTypes.PPM], subject, predicate,
							object);
					int ppmId = idSet.getNextId();
					this.addCiphertextId(ppmE[1], ppmId);
					graph.addCiphertext(ppmId, ppmE[0]);

					byte[][] pmpE = encrypter.encryptPMP(n,
							basicKeys[BasicTypes.PMP], subject, predicate,
							object);
					int pmpId = idSet.getNextId();
					this.addCiphertextId(pmpE[1], pmpId);
					graph.addCiphertext(pmpId, pmpE[0]);

					byte[][] mppE = encrypter.encryptMPP(n,
							basicKeys[BasicTypes.MPP], subject, predicate,
							object);
					int mppId = idSet.getNextId();
					this.addCiphertextId(mppE[1], mppId);
					graph.addCiphertext(mppId, mppE[0]);

					byte[][] pppE = encrypter.encryptPPP(n,
							basicKeys[BasicTypes.PPP], subject, predicate,
							object);
					int pppId = idSet.getNextId();
					this.addCiphertextId(pppE[1], pppId);
					graph.addCiphertext(pppId, pppE[0]);
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}

			return new IndexedGraph(graph, this.createIndexTree());
		}
		catch (CryptoException e) {
			throw e;
		}
		catch (Exception e) {
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}

	public void printCiphertextIds() {
		for (ByteArray encKey : this.ciphertextSets.keySet()) {

			String values = "";
			for (int i : this.ciphertextSets.get(encKey))
				values += i + ", ";

			System.out.println(new String(encKey.getArray(),
					Constants.STRING_CHARSET)
					+ ":\t["
					+ values.substring(0, values.length() - 2) + "]");
		}
	}

	public void printTree(Map<ByteArray, byte[]> indexTree) {
		for (ByteArray indexKey : indexTree.keySet()) {

			System.out.println("indexKey = " + indexKey.toString());

			String values = "";
			for (int i : indexTree.get(indexKey))
				values += i + ", ";

			System.out.println("values   = " + values);
		}
	}
}
