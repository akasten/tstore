# T-Store: Searching in Encrypted Graph Data

T-Store is an approach for searching in encrypted RDF graphs. It restricts access to particular triples of a plaintext graph to authorized parties only by allowing these parties to perform queries on the corresponding ciphertext graph. Unauthorized parties are not able to access any plaintext triples and even authorized parties can only retrieve triples which match a legitimate query. Thereby, T-Store achieves confidentiality of the plaintext graph.

A fundamental design principle of T-Store is the distinction between a data owner and several users. The data owner owns the plaintext graph and manages its access. To this end, the data owner encrypts the plaintext graph and sends the resulting ciphertext graph to the users. Users are authorized by the data owner to perform queries on the ciphertext graph. The design of T-Store requires only little communication between the data owner and the users which covers the distribution of the ciphertext graph and the exchange of query authorizations. Query processing is conducted offline by the users on their local systems and does not involve the data owner or any other third party.

A detailed explanation of T-Store including a security analysis is provided in [this thesis](https://kola.opus.hbz-nrw.de/files/1393/thesis.pdf "Download the complete thesis.").
