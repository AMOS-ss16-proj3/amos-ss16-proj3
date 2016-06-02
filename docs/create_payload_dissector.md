
# How to dissecto a doip-payload

## Create your source-file

You can use one of the existing files as a template.
I recommend to copy the whole code from [doip-payload-0005.c](../src/plugins/doip/doip-payload-0005.c) and [doip-payload-0005.h](../src/plugins/doip/doip-payload-0005.h) and to name the new files properly.
It is good practice to hint the payload type you are going to dissect in the file's name as hexadecimal value (e.g. doip-payload-8001.[c|h] for payload type 0x8001).
You also have to adapt the source-file's include-directives.


## Enable dissector for compiling

For compiling we are currently using all make-files (and others) provided by wireshark.
Therefore we have to adapt their rules and have to include every source file we create into [CMakeLists.txt](../src/plugins/doip/CMakeLists.txt) and [Makefile.common](../src/plugins/doip/Makefile.common).
In *CMakeList.txt* you have to add your \*.c files to **DISSECTOR_SUPPORT_SRC**.
*Makefile.common* requires you to add your \*.c files to the list of **NONGENERATED_C_CILES** and your \*.h files to **CLEAN_HEADER_FILES**.
Do *NOT* forget the tailing backslash ("\\") at the end of every line but except the last one!






