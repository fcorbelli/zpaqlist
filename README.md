# zpaqlist
List the contents of zpaq files in more concise way  

## This is zpaqlist, a patched  ZPAQ version 6.60 
(http://mattmahoney.net/dc/zpaq.html)

## **Provided as-is, with no warranty whatsoever, by Franco Corbelli, franco@francocorbelli.com**

Software to list the contents of zpaq files in the most concise way possible, 
to reduce the time necessary for subsequent uses (e.g. from GUIs written in other languages),
on Windows.

A classic method for an extracting GUI for zpaq is to redirect the output of the command
zpaq l (list) to a temporary file, read it, parse and then process, but it takes time.

The output of zpaqlist is composed by

- version #
!1266

- version list
|      1 2019-05-12 15:42:22
|      2 2019-05-13 09:22:49
|      3 2019-05-14 17:18:06
|      4 2019-05-16 14:17:25
|      5 2019-05-16 15:30:17
|      6 2019-05-16 23:30:17
(...)

- total row number (with +)
+38915424

- sorted by version and file name (for a time machine-like use) 
- and, by default, does not duplicate identical file names.
- version_number
- datetime (or D for deleted)
- size (with dots)
- filename or ? (if not changed from previous)
Example (two record)
The file f:/zarc/ihsv/pakka/30_3/zpaqfranz.exe is 3.089.462 bytes long,
and was found in the 946 version, @ 02/10/2020 14:25:34  (European-style date format)
In the version 959 the file result deleted (not present)

-946
02/10/2020 14:25:34
3.089.462
f:/zarc/ihsv/pakka/30_3/zpaqfranz.exe
-959
D
0
?


When the size of the output is large (and can even be hundreds of MB) 
the savings both in writing (on magnetic disks), reading and parsing 
can be considerable. 

For small archives (KB) there is obviously no difference compared to zpaq

-pakka for more verbose

# How to compile (Windows)
```
g++ -s -O3  zpaqlist.cpp -o zpaqlist -static  
```
