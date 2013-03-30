wireshark-whatsapp
==================

Whatsapp dissector plugin for wireshark

Build and install
-----------------

1. Create a build directory and move to it, for example "mkdir build; cd build"
2. Generate Makefiles "cmake .."
3. Now build the plugin "make"
4. And the plugin should be built as "whatsapp.so", just copy it to the plugins folder "cp whatsapp.so ~/.wireshark/plugins/"
 
You need the wireshark headers, the glib-2.0 headers, the libcrypto headers (install openssl headers) and of course the gcc C/C++ compiler.

Usage
-----

Using the plugin it's easy. You can use it to filter whatsapp packets (although it does not work as well as I'd like) and to dissect the data of the packet.
For decryption support goto to protocol preferences, enable the data decoding and fill some decryption keys (the passwords for the accounts you are sniffing).


