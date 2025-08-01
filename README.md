# The Bouncy Castle Crypto Package For Java

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](https://www.keyfactor.com/platform/bouncy-castle-support/) (now part of Keyfactor).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Maven Public Key

The file [bc_maven_public_key.asc](bc_maven_public_key.asc) contains the public key used to sign our artifacts on Maven Central. You will need to use 

```
gpg -o bc_maven_public_key.gpg --dearmor bc_maven_public_key.asc
```

to dearmor the key before use. Once that is done, a file can be verified by using:

```
gpg --no-default-keyring --keyring ./bc_maven_public_key.gpg --verify  file_name.jar.asc file_name.jar
```

Note: the ./ is required in front of the key file name to tell gpg to look locally.

## Building overview

This project can now be built and tested with JDK21. 

If the build script detects BC_JDK8, BC_JDK11, BC_JDK17 it will add to the usual test task a dependency on test tasks 
that specifically use the JVMs addressed by those environmental variables. The script relies on JAVA_HOME for picking up Java 21 if it is use.

We support testing on specific JVMs as it is the only way to be certain the library is compatible.

## Environmental Variables

The following environmental variables can optionally point to the JAVA_HOME for each JVM version.

```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
```

## Building

The project now uses ```gradlew``` which can be invoked for example:

```
# from the root of the project

# Ensure JAVA_HOME points to JDK 21 or higher JAVA_HOME or that
# gradlew can find a java 21 installation to use.


./gradlew clean build

```

The gradle script will endeavour to verify their existence but not the correctness of their value.


## Multi-release jars and testing
Some subprojects produce multi-release jars and these jars are can be tested on different jvm versions specifically.

If the env vars are defined:
```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
```

If only a Java 21 JDK is present then the normal test task and test21 are run only.


## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory. From JDK 1.4 and later the JCE ships with the JVM, the source for later JDKs follows the progress that was made in the later versions of the JCE. If you are using a later version of the JDK which comes with a JCE install please **do not** include the jce directory as a source file as it will clash with the JCE API installed with your JDK.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **util** module is the home for code which is used by other modules that does not need to be in prov. At the moment this is largely ASN.1 classes for the PKIX module.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The **tls** module is the home for code used to a general TLS API and JSSE Provider.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.

**Important**: You will also need to check out the [bc-test-data](https://github.com/bcgit/bc-test-data) repository at the same level as the bc-java repository if you want to run the tests.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.bouncycastle.crypto.test**

*   **org.bouncycastle.jce.provider.test**

*   **org.bouncycastle.cms.test**

*   **org.bouncycastle.mail.smime.test**

*   **org.bouncycastle.openpgp.test**

*   **org.bouncycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.bouncycastle.mail.smime.examples**

*   **org.bouncycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request@bouncycastle.org](mailto:announce-crypto-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request@bouncycastle.org](mailto:dev-crypto-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
<<<<<<< HEAD
# bc-java-x9.146
bc-java with X9.146 TLS extension support.
=======
# The Bouncy Castle Crypto Package For Java

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](https://www.keyfactor.com/platform/bouncy-castle-support/) (now part of Keyfactor).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Maven Public Key

The file [bc_maven_public_key.asc](bc_maven_public_key.asc) contains the public key used to sign our artifacts on Maven Central. You will need to use 

```
gpg -o bc_maven_public_key.gpg --dearmor bc_maven_public_key.asc
```

to dearmor the key before use. Once that is done, a file can be verified by using:

```
gpg --no-default-keyring --keyring ./bc_maven_public_key.gpg --verify  file_name.jar.asc file_name.jar
```

Note: the ./ is required in front of the key file name to tell gpg to look locally.

## Building overview

This project can now be built and tested with JDK21. 

If the build script detects BC_JDK8, BC_JDK11, BC_JDK17 it will add to the usual test task a dependency on test tasks 
that specifically use the JVMs addressed by those environmental variables. The script relies on JAVA_HOME for picking up Java 21 if it is use.

We support testing on specific JVMs as it is the only way to be certain the library is compatible.

## Environmental Variables

The following environmental variables can optionally point to the JAVA_HOME for each JVM version.

```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
```

## Building

The project now uses ```gradlew``` which can be invoked for example:

```
# from the root of the project

# Ensure JAVA_HOME points to JDK 21 or higher JAVA_HOME or that
# gradlew can find a java 21 installation to use.


./gradlew clean build

```

The gradle script will endeavour to verify their existence but not the correctness of their value.


## Multi-release jars and testing
Some subprojects produce multi-release jars and these jars are can be tested on different jvm versions specifically.

If the env vars are defined:
```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
```

If only a Java 21 JDK is present then the normal test task and test21 are run only.


## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory. From JDK 1.4 and later the JCE ships with the JVM, the source for later JDKs follows the progress that was made in the later versions of the JCE. If you are using a later version of the JDK which comes with a JCE install please **do not** include the jce directory as a source file as it will clash with the JCE API installed with your JDK.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **util** module is the home for code which is used by other modules that does not need to be in prov. At the moment this is largely ASN.1 classes for the PKIX module.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The **tls** module is the home for code used to a general TLS API and JSSE Provider.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.

**Important**: You will also need to check out the [bc-test-data](https://github.com/bcgit/bc-test-data) repository at the same level as the bc-java repository if you want to run the tests.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.bouncycastle.crypto.test**

*   **org.bouncycastle.jce.provider.test**

*   **org.bouncycastle.cms.test**

*   **org.bouncycastle.mail.smime.test**

*   **org.bouncycastle.openpgp.test**

*   **org.bouncycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.bouncycastle.mail.smime.examples**

*   **org.bouncycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request@bouncycastle.org](mailto:announce-crypto-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request@bouncycastle.org](mailto:dev-crypto-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
>>>>>>> refs/heads/x9.146-wolfssl-interop
