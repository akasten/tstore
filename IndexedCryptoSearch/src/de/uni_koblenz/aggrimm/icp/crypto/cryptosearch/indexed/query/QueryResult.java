package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.indexed.query;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class QueryResult implements Iterable<List<String>> {

	private List<String> resultVars;
	private List<List<String>> results;

	public QueryResult() {
		this.resultVars = new ArrayList<String>(0);
		this.results = new ArrayList<List<String>>(0);
	}
	
	public int size() {
		return this.results.size();
	}

	public QueryResult join(Iterator<String[]> queryResult, String var0,
			String var1, String var2) throws IOException {
		int index0 = this.resultVars.indexOf(var0);
		int index1 = this.resultVars.indexOf(var1);
		int index2 = this.resultVars.indexOf(var2);

		QueryResult joined = new QueryResult();

		// If the former result is empty, just add the results of the new
		// query.
		if (this.resultVars.size() == 0) {
			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(3);
			joined.resultVars.add(var0);
			joined.resultVars.add(var1);
			joined.resultVars.add(var2);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();
				ArrayList<String> entry = new ArrayList<String>(3);
				entry.add(str[0]);
				entry.add(str[1]);
				entry.add(str[2]);
				joined.results.add(entry);
			}
		}
		// If the former result and the new query result do not have any
		// common
		// variables, perform a cross join.
		else if (index0 < 0 && index1 < 0 && index2 < 0) {
			int newSize = this.resultVars.size() + 3;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.resultVars.add(var1);
			joined.resultVars.add(var2);
			joined.results = new LinkedList<List<String>>();

			// Perform the actual join operation. A cross join is the
			// Cartesian
			// product of both tables to be joined. In this case, this
			// corresponds to the product of the former result and the new
			// query
			// result.
			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results) {
					ArrayList<String> entry = new ArrayList<String>(newSize);
					entry.addAll(res);
					entry.add(str[0]);
					entry.add(str[1]);
					entry.add(str[2]);
					joined.results.add(entry);
				}
			}
		}
		// If at least one variable of the new query result is contained in
		// the
		// former result, perform a natural join. This can be further
		// distinguished between seven different cases.
		else if (index0 >= 0 && index1 < 0 && index2 < 0) {
			int newSize = this.resultVars.size() + 2;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var1);
			joined.resultVars.add(var2);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[0].equals(res.get(index0))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[1]);
						entry.add(str[2]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 < 0 && index1 >= 0 && index2 < 0) {
			int newSize = this.resultVars.size() + 2;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.resultVars.add(var2);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[1].equals(res.get(index1))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[0]);
						entry.add(str[2]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 < 0 && index1 < 0 && index2 >= 0) {
			int newSize = this.resultVars.size() + 2;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.resultVars.add(var1);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[2].equals(res.get(index2))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[0]);
						entry.add(str[1]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 < 0 && index1 >= 0 && index2 >= 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[1].equals(res.get(index1))
							&& str[2].equals(res.get(index2))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[0]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 >= 0 && index1 < 0 && index2 >= 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var1);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[0].equals(res.get(index0))
							&& str[2].equals(res.get(index2))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[1]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 >= 0 && index1 >= 0 && index2 < 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var2);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[0].equals(res.get(index0))
							&& str[1].equals(res.get(index1))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[2]);
						joined.results.add(entry);
					}
			}
		}
		else { // (index0 >= 0 && index1 >= 0 && index2 >= 0)

			joined.resultVars = this.resultVars;
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					if (str[0].equals(res.get(index0))
							&& str[1].equals(res.get(index1))
							&& str[2].equals(res.get(index2)))
						joined.results.add(res);
			}
		}

		return joined;
	}

	public QueryResult join(Iterator<String[]> queryResult, String var0,
			String var1) throws IOException {
		int index0 = this.resultVars.indexOf(var0);
		int index1 = this.resultVars.indexOf(var1);

		QueryResult joined = new QueryResult();

		// If the former result is empty, just add the results of the new
		// query.
		if (this.resultVars.size() == 0) {
			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(2);
			joined.resultVars.add(var0);
			joined.resultVars.add(var1);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();
				ArrayList<String> entry = new ArrayList<String>(2);
				entry.add(str[0]);
				entry.add(str[1]);
				joined.results.add(entry);
			}
		}
		// If the former result and the new query result do not have any
		// common
		// variables, perform a cross join.
		else if (index0 < 0 && index1 < 0) {
			int newSize = this.resultVars.size() + 2;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.resultVars.add(var1);
			joined.results = new LinkedList<List<String>>();

			// Perform the actual join operation. A cross join is the
			// Cartesian
			// product of both tables to be joined. In this case, this
			// corresponds to the product of the former result and the new
			// query
			// result.
			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results) {
					ArrayList<String> entry = new ArrayList<String>(newSize);
					entry.addAll(res);
					entry.add(str[0]);
					entry.add(str[1]);
					joined.results.add(entry);
				}
			}
		}
		// If at least one variable of the new query result is contained in
		// the
		// former result, perform a natural join. This can be further
		// distinguished between three different cases.
		else if (index0 >= 0 && index1 < 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var1);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[0].equals(res.get(index0))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[1]);
						joined.results.add(entry);
					}
			}
		}
		else if (index0 < 0 && index1 >= 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var0);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str[1].equals(res.get(index1))) {
						ArrayList<String> entry = new ArrayList<String>(newSize);
						entry.addAll(res);
						entry.add(str[0]);
						joined.results.add(entry);
					}
			}
		}
		else { // (index0 >= 0 && index1 >= 0)

			joined.resultVars = this.resultVars;
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String[] str = queryResult.next();

				for (List<String> res : this.results) {
					if (str[0].equals(res.get(index0))
							&& str[1].equals(res.get(index1)))
						joined.results.add(res);
				}
			}
		}

		return joined;
	}

	public QueryResult join(Iterator<String> queryResult, String var)
			throws IOException {

		int index = this.resultVars.indexOf(var);
		QueryResult joined = new QueryResult();

		// If the former result is empty, just add the results of the new
		// query.
		if (this.resultVars.size() == 0) {
			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(1);
			joined.resultVars.add(var);
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String str = queryResult.next();
				ArrayList<String> entry = new ArrayList<String>(1);
				entry.add(str);
				joined.results.add(entry);
			}
		}
		// If the former result and the new query result do not have any
		// common
		// variables, perform a cross join.
		else if (index < 0) {
			int newSize = this.resultVars.size() + 1;

			// Create a new list and add the variables of the former result
			// to
			// this list.
			joined.resultVars = new ArrayList<String>(newSize);
			joined.resultVars.addAll(this.resultVars);
			joined.resultVars.add(var);
			joined.results = new LinkedList<List<String>>();

			// Perform the actual join operation. A cross join is the
			// Cartesian
			// product of both tables to be joined. In this case, this
			// corresponds to the product of the former result and the new
			// query
			// result.
			while (queryResult.hasNext()) {
				String str = queryResult.next();

				for (List<String> res : this.results) {
					ArrayList<String> entry = new ArrayList<String>(newSize);
					entry.addAll(res);
					entry.add(str);
					joined.results.add(entry);
				}
			}
		}
		else {
			// If the variable of the new query result is contained in the
			// former result, perform a natural join. In the case of only
			// one
			// query variable, the natural join just filters the entries in
			// the
			// former result. In other words, the returned QueryResult
			// contains
			// at most as many entries as the former result and exactly the
			// same
			// number of columns.
			joined.resultVars = this.resultVars;
			joined.results = new LinkedList<List<String>>();

			while (queryResult.hasNext()) {
				String str = queryResult.next();

				for (List<String> res : this.results)
					// The actual variable match.
					if (str.equals(res.get(index)))
						joined.results.add(res);
			}
		}

		return joined;
	}

	public void print() {
		print(System.out);
	}

	public void print(PrintStream out) {
		out.print("\t");
		for (String s : this.resultVars) {
			out.print(s + "\t");
		}
		out.println();

		int i = 0;
		for (List<String> res : this.results) {
			out.print(++i + "\t");
			for (String s : res) {
				out.print(s + "\t");
			}
			out.println();
		}
	}

	@Override
	public Iterator<List<String>> iterator() {
		return this.results.iterator();
	}

}
