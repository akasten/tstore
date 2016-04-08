package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.data;

/*
 * Copyright (C) 2008 Andreas Schultz
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import benchmark.testdriver.AbstractParameterPool;
import benchmark.testdriver.LocalSPARQLParameterPool;
import benchmark.testdriver.Query;
import benchmark.testdriver.TestDriverDefaultValues;

public class QueryCreator {

	/**
	 * Store the created queries.
	 */
	private Map<String, Query> queries;

	/**
	 * Where to get the query parameters from protected ServerConnection server;
	 * only important for single threaded runs
	 */
	private AbstractParameterPool parameterPool;

	/**
	 * For the random number generators
	 */
	private long seed = TestDriverDefaultValues.seed;

	/**
	 * The directory created from the data generation step.
	 */
	private String dataDir;

	private String queryDirPrefix;

	public QueryCreator(int productCount) {
		this(productCount, DefaultPathNames.QUERY_BASE_DIR,
				DefaultPathNames.DATA_DIR_PREFIX,
				DefaultPathNames.QUERY_DIR_PREFIX);
	}

	public QueryCreator(int productCount, String queryBaseDir,
			String dataDirPrefix, String queryDirPrefix) {
		this.dataDir = dataDirPrefix + productCount;
		this.queryDirPrefix = queryDirPrefix + productCount;

		this.parameterPool = new LocalSPARQLParameterPool(new File(dataDir),
				this.seed);

		initQueries(queryBaseDir);
	}

	private void initQueries(String queryBaseDir) {
		if (!queryBaseDir.endsWith("/"))
			queryBaseDir += "/";

		List<String> queryNumbers = getQueryIDs(new File(queryBaseDir
				+ "querymix.txt"));
		this.queries = new HashMap<String, Query>(queryNumbers.size());

		for (String qnr : queryNumbers) {
			File queryFile = new File(queryBaseDir, "query" + qnr + ".txt");
			File queryDescFile = new File(queryBaseDir, "query" + qnr
					+ "_desc.txt");
			this.queries.put(qnr, new Query(queryFile, queryDescFile, "%"));
		}
	}

	private List<String> getQueryIDs(File file) {
		List<String> querIDs = new ArrayList<String>();

		try {
			BufferedReader idReader = new BufferedReader(new InputStreamReader(
					new FileInputStream(file)));

			String line = null;
			while ((line = idReader.readLine()) != null) {
				StringTokenizer st = new StringTokenizer(line);
				while (st.hasMoreTokens()) {
					querIDs.add(st.nextToken());
				}
			}

			idReader.close();
		}
		catch (IOException e) {
			System.err.println("Error processing query mix file: " + file);
			System.exit(-1);
		}
		return querIDs;
	}

	public void createQueries(int numberOfRuns) {
		
		String queriesDirPath = this.queryDirPrefix + "_" + numberOfRuns;

		File allQueriesDir = new File(queriesDirPath);
		if (allQueriesDir.exists()) {
			System.out
					.println("Query directory already exists. Skipping creation of new");
			System.out.println("queries.");
			return;
		}

		allQueriesDir.mkdir();

		for (String qnr : this.queries.keySet()) {
			String queriesDirName = queriesDirPath + "/query_" + qnr;

			File queriesDir = new File(queriesDirName);
			if (!queriesDir.exists())
				queriesDir.mkdir();

			for (int i = 0; i < numberOfRuns; ++i) {

				Query q = this.queries.get(qnr);

				Object[] queryParameters = this.parameterPool
						.getParametersForQuery(q);
				q.setParameters(queryParameters);

				try {
					FileOutputStream outStream = new FileOutputStream(
							queriesDirName + "/" + (i + 1) + ".sparql");
					outStream.write(q.getQueryString().getBytes());
					outStream.close();
				}
				catch (FileNotFoundException e) {
					System.err.println("File not found.");
				}
				catch (IOException e) {
					System.err.println("Could not write to file.");
				}
			}
		}
	}

	public String getDataDir() {
		return this.dataDir;
	}

	public String getQueryDirPrefix() {
		return this.queryDirPrefix;
	}
	
	public String getQueryDir(int numberOfRuns) {
		return this.queryDirPrefix + "_" + numberOfRuns;
	}
}
