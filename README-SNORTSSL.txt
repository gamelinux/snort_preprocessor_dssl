Products | SnortSSL (beta2)

New! Snort SSL beta2 is available for download

SnortSSL is a free, open source SSL decryption plug-in for Snort — the most popular open source Network Intrusion Detection System. SnortSSL is implemented as a dynamic Snort preprocessor that uses DSSL library to decrypt SSL traffic.
It does the following:

    * Processes every network packet received by Snort;
    * Filters SSL traffic according to its configuration;
    * Reassembles TCP, decodes and decrypts SSL;
    * Creates new network packets containing decrypted plaintext and passes them back to Snort for further processing (much like Snort's own stream4 module)

SnortSSL is currently in a beta stage; changes in plugin's functionality, installation, and configuration are expected.
What's New in Beta2?

SnortSSL beta2 addresses multiple issues with preprocessor configuration settings and fixes external dll dependency issues ("error 126" in the Snort log).

Please note that the configuration format has slightly changed in beta2: now you don't need to include the keyfile, pwdfile, and pwd parameters in double quotation marks ("")
Installation

The easiest way to install SnortSSL plug-in is to download the compiled binary module for your platform. Currently, SnortSSL beta is available only for Microsoft Windows. Versions for Linux and other Operating Systems are currently in development.

Installing SnortSSL is simple:

   1. Copy sf-ssl.dll (on Windows) or sf-ssl.so (on Linux) to the snort_dynamicpreprocessor directory of your Snort installation.
   2. Add the preprocessor declarartion to the Snort config file:

      dynamicpreprocessor file sf-ssl.dll

   3. Configure the ssl preprocessor by adding something like the following to your Snort config file:

      preprocessor ssl: server \
      	{ ip 192.168.1.100 \
      	  port 443 \
      	  keyfile your-ssl-server-key.pem \
      	 [ pwd server-key-file-password | pwdfile password-file-path ] \
      	}

      Note that pwd and pwdfile parameters are mutually exclusive and only needed if your SSL server's private key file is itself encrypted. For security reason, we strongly recommend using pwdfile whenever a password option is needed!
   4. Start Snort.
   5. Check Snort's log to verify that the ssl preprocessor initialized successfully.

Building SnortSSL

Alternatively to using the compiled binaries, you can download SnortSSL source code and build the plug-in yourself. This is recommended for advanced users as the build procedure is fairly complicated:
Building SnortSSL on Windows

   1. Download and unzip Snort 2.6 source code into the folder where you plan to build it.
   2. Note that Snort (at least the 2.6.1.1 version ) requires tools from Cygwin package installed at c:\cygwin
   3. Unzip SnortSSL.zip into src/dynamic-preprocessors/ directory of the Snort source tree so that it'll have a /ssl subdirectory.
   4. SnortSSL Windows package already has DSSL library sources that should be located in sll/dssl/libdssl/ directory.
   5. Download and unpack DSSL prerequisites into separate directories under /ssl/dssl/one so that the resulting directory tree looks like the following:

      /ssl/
        dssl/
          libdssl/
          openssl/
            apps/
            bugs/
            ...
          WdpPack/
            docs/
            Include/
            Lib/
            ...

   6. Add /ssl/sf_ssl.vcproj and ssl/dssl/libdssl/libdssl.vcproj project files to the Snort solution file at /src/win32/WIN32-prj/snort.sln.
   7. Use Debug-DSSL_NO_PCAP and Release-DSSL_NO_PCAP libdssl.vcproj configurations to build with sf_ssl
   8. Build the solution, adjust the include and output files location as necessary if errors occur.

