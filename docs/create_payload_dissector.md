
# How to dissect a doip-payload

This file provides a short overview about steps required to implement a doip payload type dissector.

## Create your source-file

You can use one of the existing files as a template.
I recommend to copy the whole code from [doip-payload-0005.c](../src/plugins/doip/doip-payload-0005.c) and [doip-payload-0005.h](../src/plugins/doip/doip-payload-0005.h) and to name the new files properly.
It is good practice to hint the payload type you are going to dissect in the file's name as hexadecimal value (e.g. doip-payload-8001.[c|h] for payload type 0x8001).
You also have to adapt the source-file's include-directives.


## Enable dissector for compiling

For compiling we are currently using all make-files (and others) provided by wireshark.
Therefore we have to adapt their rules and have to include every source file we create into [CMakeLists.txt](../src/plugins/doip/CMakeLists.txt) and [Makefile.common](../src/plugins/doip/Makefile.common).
In *CMakeList.txt* you have to add your \*.c files to **DISSECTOR\_SUPPORT_SRC**.

*Makefile.common* requires you to add your \*.c files to the list of **NONGENERATED_C_FILES** and your \*.h files to **CLEAN\_HEADER\_FILES**.
Do *NOT* forget the tailing backslash ("\\") at the end of every line except the last one!

## Make payload type available for doip-dissector
After creating all required files and adding them to various Makefiles as described above it is required to add the dissector to [doip-payload-handler.c](../src/plugins/doip/doip-payload-handler.c).

1. Add your payload-type-dissectors headerfile to doip-payload-handler.c
2. Add your register-function to **register\_proto\_doip\_payload()**
3. Add your dissect-function to **find\_matching\_payload\_handler()**


## Implementing your dissector
An in-depth explanation for implementing a dissector is provided by wireshark and can be found at [README.dissector](https://github.com/wireshark/wireshark/blob/master-1.12/doc/README.dissector).  
Especially relevant are chapters 1.5 to 1.7.

A rather short introduction, however, will also be given in this document.  

### Register your fields

1. Delete all global variables and function-implementations you copied from the original dissector.
2. For each field you want to register create a static global variable of type **gint**. The variable name shoud have the prefix **hf\_** and be set to -1.
3. Add a global static gint variable with the payload's type name and prefix **ett\_** and set it to -1.
4. Next you have to create a static array of type hf\_register\_info called "hf" in your register-function.
This array holds a reference to your variables defined in step 2 and a struct header\_field\_info.
Please consult chapter 1.5 and 1.5.1 of README.dissector for further details.
5. Create another array which holds pointers to gint's (gint \*) called **ett** and insert a pointer to your ett\_\* variable.
6. Finally register your header-fields from step 4 and ett-array from step 3 by calling  

        proto\_register\_field_array(proto\_doip, hf, array\_length(hf));

    and

        proto\_register\_subtree\_array(ett, array\_length(ett));


### Fill your fields

All fields defined in **register\_proto\_doip\_payload\_\*()** can now be filled at **dissect\_payload\_\*()**.
In order to do so you require the corresponding **tvbuff\_t \*** which holds the doip message's data.  
**retrieve\_tvbuff()** defined in **doip-header.h** can be used to do so.
Next you have to create a subtree using your **ett\_\*** variable.
    proto\_item\_add\_subtree(pitem, ett\_\*);  
This tree will be used to tell wireshark where it shall insert values defined in the next step.  
Wireshark enforces referencing values within a **tvbuff\_t**  rather than  inserting values directly.
Therefor you have to define the position and length of a type you want to insert to the tree.
As the ISO does mostly gives a starting position relative to the payload's beginning, you either have to calculate the total offset, or use **insert\_item\_to\_tree()** defined in **doip-helper.h** which will take a relative offset and calculate the absolute offset.  
Usage may look like:

    insert\_item\_to\_tree(tree, hf\_source\_addr, tvb, REL\_SRC\_ADDR\_POS, SRC\_ADDR\_LEN, ENC\_BIG\_ENDIAN);



## insert column info


## Additional remarks
- When pushing to branch master, please only commit compiling code!
- The current compiler configuration prints all warnings, but does not prevent compiling if warnings are present. As a good practice please only push code which does not create any warnings.






