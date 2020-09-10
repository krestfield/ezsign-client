Krestfield EzSign Client for Java
---------------------------------

The client interface to the EzSign server for the generation and verification of digital signatures

The library is also available as a .NET dll

REST interface is also available.  Details here:
  https://s3.eu-west-2.amazonaws.com/krestfield/restapispecification.pdf

Usage:
```java
  String serverIPAddress = "127.0.0.1";
  int serverPortNumber = 5656;
  String channelName = "TEST";
  byte[] dataToSign = "Hello".getBytes();
  boolean dataIsDigest = false;
  byte[] signature = null;
  
  // Create the client
  EzSignClient client = new EzSignClient(serverIPAddress, serverPortNumber);

  // Sign some data
  // All items relating to signature algorithm (RSA or ECDSA), hash algorithm
  // and key store (e.g. which HSM) are configured at the server
  signature = client.signData(channelName, dataToSign, false);

  // Verify the signature
  client.verifySignature(channelName, signature, dataToSign, false);
```  



