package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.index;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.ByteArray;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Constants;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core.Utils;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoBase;
import de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.crypto.CryptoException;

public class IndexTree extends CryptoBase {

	private Map<ByteArray, byte[]> indexTree;

	IndexTree(Map<ByteArray, byte[]> indexTree, byte[] iv)
			throws CryptoException {
		super(iv);

		this.indexTree = indexTree;
	}

	/**
	 * Factory method for loading an index tree from the given file.
	 * 
	 * @param fileName
	 *            The filename of the file containing the index tree to be
	 *            loaded.
	 * @param iv
	 *            The initialization vector of the index tree. Used for
	 *            decrypting the arrays.
	 * @return The loaded index tree.
	 * @throws IOException
	 *             Will be thrown if the index tree cannot be written into the
	 *             file.
	 * @throws CryptoException
	 *             Will be thrown if the cryptographic stuff cannot be
	 *             initialized.
	 */
	public static IndexTree loadIndexTree(String fileName, byte[] iv)
			throws IOException, CryptoException {
		return loadIndexTree(new File(fileName), iv);
	}

	/**
	 * Factory method for loading an index tree from the given file.
	 * 
	 * @param indexFile
	 *            The file containing the index tree to be loaded.
	 * @param iv
	 *            The initialization vector of the index tree. Used for
	 *            decrypting the arrays.
	 * @return The loaded index tree.
	 * @throws IOException
	 *             Will be thrown if the index tree cannot be written into the
	 *             file.
	 * @throws CryptoException
	 *             Will be thrown if the cryptographic stuff cannot be
	 *             initialized.
	 */
	public static IndexTree loadIndexTree(File indexFile, byte[] iv)
			throws IOException, CryptoException {

		// Create an initial indexTree.
		Map<ByteArray, byte[]> indexTree = new TreeMap<ByteArray, byte[]>();

		BufferedInputStream streamReader = new BufferedInputStream(
				new FileInputStream(indexFile));

		// HASH_LENGTH stores the number of bits for a hash value. In order to
		// get the number of bytes, divide it by 8.
		int indexKeySize = Constants.HASH_LENGTH / 8;

		// Each array consists of ARRAY_SIZE integer values which each consist
		// of 4 bytes. Furthermore, the array contains one byte storing whether
		// or not there are more arrays of the same set. All these values are
		// padded such that the resulting array size is a multiple of
		// ARRAY_SIZE.
		int arraySize = 1 + Constants.ARRAY_SIZE * 4 + Constants.ARRAY_PADDING;

		// Read as long as there are at least indexKeySize bytes left.
		while (streamReader.available() > indexKeySize) {

			// Read the index key.
			byte[] indexKeyArray = new byte[indexKeySize];
			streamReader.read(indexKeyArray);

			// Read the encrypted array.
			byte[] encArray = new byte[arraySize];
			streamReader.read(encArray);

			// Add the encryped array to the Map.
			indexTree.put(new ByteArray(indexKeyArray), encArray);
		}

		streamReader.close();

		return new IndexTree(indexTree, iv);
	}

	/**
	 * Stores the index tree in the given file.
	 * 
	 * @param fileName
	 *            The filename of the file into which the index tree shall be
	 *            written.
	 * @throws IOException
	 *             Will be thrown if the index tree cannot be written into the
	 *             file.
	 */
	public void writeToFile(String fileName) throws IOException {
		writeToFile(new File(fileName));
	}

	/**
	 * Stores the index tree in the given file.
	 * 
	 * @param indexFile
	 *            The file into which the index tree shall be written.
	 * @throws IOException
	 *             Will be thrown if the index tree cannot be written into the
	 *             file.
	 */
	public void writeToFile(File indexFile) throws IOException {

		BufferedOutputStream streamWriter = new BufferedOutputStream(
				new FileOutputStream(indexFile));

		// Format for writing the triples:
		// indexKey - ciphertext
		// All indexKeys and all ciphertexts have the same size. Thus, there is
		// no need to also store the size in the file.
		for (ByteArray bArr : this.indexTree.keySet()) {

			// Write the indexKey.
			streamWriter.write(bArr.getArray());

			// Write the encrypted array.
			streamWriter.write(this.indexTree.get(bArr));
		}

		streamWriter.close();
	}

	/**
	 * Retrieves a set of of ids of all ciphertexts which can be decrypted using
	 * the given encryption key. Thus, these ciphertexts answer the query
	 * encoded into the encryption key.
	 * 
	 * @param encryptionKey
	 *            The encryption key for which all ciphertext ids shall be
	 *            retrieved.
	 * @return The set of all ciphertext ids. May be empty.
	 * @throws CryptoException
	 *             Will be thrown if decrypting an array fails.
	 */
	public Collection<Integer> getCiphertextIds(byte[] encryptionKey)
			throws CryptoException {

		// Store the resulting set.
		Collection<Integer> result = new LinkedList<Integer>();

		// Byte arrays to be re-used for computing the index keys.
		byte[] idArray;
		byte[] indexKey = new byte[encryptionKey.length + 4];
		;
		byte[] encArray;

		// The local id of the first array always starts with 0.
		int arrayId = 1;

		// Read as many arrays as there are in the index tree.
		boolean moreArrays = true;
		while (moreArrays) {

			// Create a new index key. The key is based on the array id and on
			// the encryption key.
			idArray = Utils.intToByteArray(arrayId++);
			System.arraycopy(encryptionKey, 0, indexKey, 0,
					encryptionKey.length);
			System.arraycopy(idArray, 0, indexKey, encryptionKey.length, 4);

			// Retrieve the encrypted array from the index tree.
			encArray = this.indexTree.get(new ByteArray(this.digester
					.digest(indexKey)));

			// If the array is null, return the current result. This may also be
			// the case if the index key does not index anything at all.
			if (encArray == null)
				moreArrays = false;
			else
				// Otherwise, decrypt the current array and add its ids to the
				// set.
				moreArrays = decryptArray(encryptionKey, encArray, result);
		}

		return result;
	}

	/**
	 * Decrypts an encrypted array of ciphertext ids and stores the ids in the
	 * given Set of integers. The return value marks whether or not the current
	 * array is the last of its set.
	 * 
	 * @param encryptionKey
	 *            The key used for decrypting the array.
	 * @param array
	 *            The byte array to be decrypted.
	 * @param idset
	 *            The set of ids which is used as return value.
	 * @return <code>true</code> if there are more arrays of the same set and
	 *         <code>false</code> otherwise.
	 * @throws CryptoException
	 *             Will be thrown if anything goes wrong.
	 */
	private boolean decryptArray(byte[] encryptionKey, byte[] array,
			Collection<Integer> idset) throws CryptoException {
		try {
			// Initialize the encryption stuff.
			this.cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(
					encryptionKey, 0, Constants.SECRET_KEY_SPEC_LENGTH,
					Constants.KEY_ALGORITHM), new IvParameterSpec(this.iv));

			// Only continue if the encrypted array has the correct block size.
			if (array.length % Constants.BLOCK_SIZE != 0) {
				System.out.println("WRONG BLOCK SIZE");
				return false;
			}

			// Decrypt the array.
			byte[] decBytes = this.cipher.update(array, 0, array.length);

			// Extract the integers from the array. There are exactly ARRAY_SIZE
			// values to be extracted.
			for (int i = 0; i < Constants.ARRAY_SIZE; ++i) {

				// Each integer is represented as 4 bytes. The first byte of the
				// whole array stores the information about whether or not there
				// are more arrays of the same set.
				int v = Utils.bytesToInt(decBytes[1 + i * 4],
						decBytes[2 + i * 4], decBytes[3 + i * 4],
						decBytes[4 + i * 4]);

				// Only add the decrypted integer to the set if it is not 0. The
				// value 0 is used for padding. If the first 0 is reached, the
				// loop can be stopped.
				if (v != 0)
					idset.add(v);
				else
					break;
			}

			// The first byte stores whether or not there are more arrays of the
			// same set. If this is the case, the byte is 1.
			return decBytes[0] == 1;
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new CryptoException(e.getMessage(), e.getCause());
		}
	}

	public void printStuff() {

		System.out.println("Printing stuff...");

		System.out.println("Number of different keys : "
				+ this.indexTree.keySet().size());

		// for(ByteArray arr : this.indexTree.keySet())
		// System.out.println(arr.length());

	}

}
