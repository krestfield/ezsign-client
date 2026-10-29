Krestfield EzSign Client for Java
---------------------------------

The client interface to the EzSign server for the generation and verification of digital signatures, encryption,
decryption and random number generation

The library is also available as a .NET dll

From version 4.6.0 the same client can use either of the server's interfaces:

* The **socket API** (the default), as in previous versions. Optionally protected with an auth code and/or TLS
* The **REST API** (HTTPS and JSON). The client authenticates with an API token or a TLS client certificate

The calls (signData, verifySignature, encryptData etc.) and the exceptions they throw are the same for both, so an
application can switch between them by changing only how the client is created

Requires Java 8 or later. There are no other dependencies


Usage
-----

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
  signature = client.signData(channelName, dataToSign, dataIsDigest);

  // Verify the signature
  client.verifySignature(channelName, signature, dataToSign, dataIsDigest);
```


Creating the Client
-------------------

**Socket API**

```java
  // No auth code
  EzSignClient client = new EzSignClient("127.0.0.1", 5656);

  // With the auth code set as server.authCode on the server
  EzSignClient client = new EzSignClient("127.0.0.1", 5656, "the-auth-code");

  // Over TLS. The server's certificate must be trusted and valid for the host name used
  EzSignClient client = new EzSignClient("ezsign.example.com", 5656)
          .useTls()
          .useTrustStore("truststore.p12", "password", "PKCS12");

  // Over TLS, with a client certificate
  EzSignClient client = new EzSignClient("ezsign.example.com", 5656)
          .useClientTls("client.p12", "password", "PKCS12")
          .useTrustStore("truststore.p12", "password", "PKCS12");
```

**REST API with an API token**

```java
  EzSignClient client = new EzSignClient("ezsign.example.com", 8443)
          .useRestApi()
          .useApiToken(apiToken)
          .useTrustStore("truststore.p12", "password", "PKCS12");
```

**REST API with a client certificate**

```java
  EzSignClient client = new EzSignClient("ezsign.example.com", 8443)
          .useRestApi()
          .useClientTls("client.p12", "password", "PKCS12")
          .useTrustStore("truststore.p12", "password", "PKCS12");
```

If no trust store is set, the Java trust store is used (including the javax.net.ssl.trustStore system property).
The same applies to the javax.net.ssl.keyStore system property if no client key store is set

If the server's REST API has TLS turned off (server.restapi.useTls=false), use `useRestApi(false)`. An API token is
then required and is sent in clear, so this is only suitable when client and server are on the same machine

The client can be created once and used from many threads. Socket API requests are sent one at a time per client;
REST API requests can run at the same time


Switching Between the APIs
--------------------------

An application already using the socket API can move to the REST API by:

1. Using this version of the client jar
2. Changing the port to the REST API port (server.restapi.port)
3. Adding `useRestApi()` and the authentication: `useApiToken(...)` or `useClientTls(...)`
4. Removing the auth code, which is not used by the REST API

No other code changes are needed. To revert, remove `useRestApi()` and the API token and set the socket port (and
auth code) again. Mixing the settings (e.g. an auth code with the REST API, or an API token with the socket API) is
reported as a KEzSignException on the first call, rather than being silently ignored

Keeping the connection details in a properties file (below) means the switch needs no code change at all


Creating the Client from Properties
-----------------------------------

```java
  EzSignClient client = EzSignClient.fromProperties("ezsign-client.properties");
```

Socket API:

```
ezsign.api=socket
ezsign.host=127.0.0.1
ezsign.port=5656
ezsign.authCodeFile=/etc/ezsign/authcode.txt
```

REST API:

```
ezsign.api=rest
ezsign.host=ezsign.example.com
ezsign.port=8443
ezsign.apiTokenFile=/etc/ezsign/apitoken.txt
ezsign.trustStore=/etc/ezsign/truststore.p12
ezsign.trustStorePasswordFile=/etc/ezsign/truststore-password.txt
```

| Property | Description |
|---|---|
| ezsign.api | `socket` (default) or `rest` |
| ezsign.host | The server host name or IP address (required) |
| ezsign.port | The socket or REST API port (required) |
| ezsign.connectTimeoutMs | The connect timeout in milliseconds |
| ezsign.readTimeoutMs | The read timeout in milliseconds |
| ezsign.tls | Socket API: `true` to use TLS (default false). REST API: `false` to use HTTP (default true) |
| ezsign.authCode | The socket API auth code |
| ezsign.apiToken | The REST API token |
| ezsign.clientKeyStore | The client certificate key store |
| ezsign.clientKeyStorePassword | The client key store password |
| ezsign.clientKeyStoreType | The client key store type (default PKCS12) |
| ezsign.trustStore | The trust store holding the server's CA certificate |
| ezsign.trustStorePassword | The trust store password |
| ezsign.trustStoreType | The trust store type (default PKCS12) |
| ezsign.verifyHostname | `false` to turn off the host name check (default true) |

Any secret (authCode, apiToken, clientKeyStorePassword, trustStorePassword) can be read from a file instead, by
adding `File` to the property name, e.g. `ezsign.apiTokenFile`. The first line of the file is used. This keeps
secrets out of the properties file, which can then be readable by more users


Errors
------

Both APIs throw the same exceptions:

| Exception | When |
|---|---|
| KEzSignConnectException | The server could not be reached, the TLS handshake failed or (socket API) the server closed the connection without responding, usually a wrong auth code |
| KSigningException | Signing failed |
| KVerificationException | The signature did not verify |
| KPathException | The certificate path could not be built |
| KRevocationException | The revocation check failed or the certificate is revoked |
| KEncipherException | Encryption or decryption failed |
| KEzSignException | Anything else, including REST API authentication failures (401), permission failures (403) and a busy server |

REST API error messages include the HTTP status, the error code and the server's transaction ID, which can be
matched against the server log


Changes in 4.6.0
----------------

* REST API support, fromProperties, and the verifyHostname, useRestApi, useSocketApi and useApiToken settings
* With TLS, the server's host name is now checked against its certificate. If you connect by IP address and the
  certificate does not include it, either add the IP address to the certificate or call `verifyHostname(false)`
* TLS is limited to TLS 1.2 and 1.3
* useTrustStore no longer turns on TLS for the socket API on its own. Call `useTls()` (or `useClientTls(...)`)
* A response code the method does not expect is now a KEzSignException. Previously signData, encryptData etc.
  could return null
* An empty result (e.g. decrypting data with no content) is returned as an empty array, never null
* Channel names and key labels containing `~` or line breaks are rejected, as they would change the socket message
* Server error messages containing `~` are returned in full
* Each connection attempt uses a new socket, and the read timeout is set before the TLS handshake
* A response that cannot be decrypted with the auth code is reported, rather than the call failing later
