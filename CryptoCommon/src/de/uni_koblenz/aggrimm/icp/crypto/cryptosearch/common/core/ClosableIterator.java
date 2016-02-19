package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.common.core;

import java.io.Closeable;
import java.util.Iterator;

public interface ClosableIterator<T> extends Closeable, Iterator<T> {

}
