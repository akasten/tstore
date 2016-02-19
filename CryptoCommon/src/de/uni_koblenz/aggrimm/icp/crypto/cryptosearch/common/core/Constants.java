package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core;

import java.nio.charset.Charset;

public interface Constants {

	public static final Charset STRING_CHARSET = Charset.forName("UTF-8");
	
	public static final int PRIME_CERTAINTY = 100;
	
	public static final int BLOCK_SIZE = 16;
	
	public static final int AES_KEY_LENGTH = 256;
	
	public static final int SECRET_KEY_SPEC_LENGTH = 16;
	
	public static final int HASH_LENGTH = AES_KEY_LENGTH; 
	
	public static final int RSA_KEY_LENGTH = 2048;
	
	public static final String CRYPTO_ALGORITHM = "AES/CBC/NoPadding";
	
	public static final String KEY_ALGORITHM = "AES";
	
	public static final String HASH_ALGORITHM = "SHA-" + HASH_LENGTH;
	
	public static final String COMBINING_HASH_ALGORITHM = HASH_ALGORITHM;
	
	public static final byte[] SEPARATOR = new byte[] { '\0' };
	
	public static final byte[] TRIPLE_MARKER = { -46, -120, -46, -120, -46,
			-120, -46, -120, -46, -120, -46, -120, -46, -120, -46, -120 };
	
	public static final byte[] PADDING = { -21, -24, 120, -110, -80, -72, 64,
			78, -66, 70, -70, -93, -1, -75, -109, -119 };
	
	public static final byte[] SUBJECT_PADDING = new byte[] { -110, 98, -120,
			-57, -94, -92, -114, 27, 24, 52, 29, -101, 72, -83, 90, 29, -66,
			97, 12, 39, 105, 114, 119, -4, 84, -112, 27, -5, -123, 23, 107,
			-105 };
	
	public static final byte[] PREDICATE_PADDING = new byte[] { -7, 116, -34,
			27, -104, -20, -74, 48, -96, 83, 75, 105, 127, 38, 6, -66, 7, -110,
			101, -16, -124, 92, 107, 88, 108, 7, -45, 113, -99, -66, -120, 2 };
	
	public static final byte[] OBJECT_PADDING = new byte[] { -26, -79, -54, 82,
			-25, 122, 114, -70, 69, 91, -70, -21, -31, -8, 114, -12, -35, -30,
			-8, -71, -51, -48, -90, 84, 35, -105, 113, 97, -98, 8, -109, 4 };

	public static final int ARRAY_SIZE = 4;
	
	/**
	 * Choose the padding such that
	 * 
	 * (1 + {@link #ARRAY_SIZE} * 4 + {@link #ARRAY_PADDING}) % {@link #BLOCK_SIZE} == 0
	 */
	public static final int ARRAY_PADDING = 15;
}