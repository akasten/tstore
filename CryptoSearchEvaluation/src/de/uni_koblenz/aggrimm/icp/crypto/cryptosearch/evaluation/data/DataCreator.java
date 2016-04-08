package de.uni_koblenz.aggrimm.icp.crypto.cryptosearch.evaluation.data;

import java.io.File;

import benchmark.generator.Generator;

public class DataCreator {

	private String dataDir;

	private String dataSet;
	
	private int productCount;

	public DataCreator(int productCount) {
		this(productCount, DefaultPathNames.DATA_DIR_PREFIX,
				DefaultPathNames.DATA_SET_PREFIX);
	}

	public DataCreator(int productCount, String dataDirPrefix,
			String dataSetPrefix) {
		this.dataDir = dataDirPrefix + productCount;
		this.dataSet = dataSetPrefix + productCount;
		this.productCount = productCount;
	}

	public void createDataSet() {
		if (new File(this.dataDir).exists())
			System.out.println("Dataset already exists. Skipping creation.");
		else
			Generator.main(new String[] { "-pc", "" + this.productCount, "-dir",
					this.dataDir, "-fn", this.dataSet, });
	}

	public String getDataDir() {
		return dataDir;
	}

	public String getDataSet() {
		return dataSet;
	}
}
