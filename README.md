# zpaqlist
List the contents of zpaq files in more concise way  
A patched zpaq 6.60 (http://mattmahoney.net/dc/zpaq.html)

## **Provided as-is, with no warranty whatsoever, by Franco Corbelli, franco@francocorbelli.com**

More concise and easier to parse output: reducing the time necessary for subsequent use (e.g. GUIs) on Windows.  

### Why?

_When the size of the output is large (can become hundreds of MB) the savings both in writing (on magnetic disks), reading and parsing can be considerable_  

_For small archives (KB) there is obviously no difference compared to zpaq's time_  

### What?  

A classic method for an extracting GUI for zpaq is to redirect the output of the command
zpaq l (list) to a temporary file, read , parse and then process, but it takes time, even minutes.

The output of zpaqlist is composed by
- version # with !. In this example, 1266
```
!1266
```

- version list, with fixed-length version number, datetime (std format)
```
|      1 2019-05-12 15:42:22
|      2 2019-05-13 09:22:49
|      3 2019-05-14 17:18:06
|      4 2019-05-16 14:17:25
|      5 2019-05-16 15:30:17
|      6 2019-05-16 23:30:17
(...)
```

- total row number (with +), in this example 38+ millions to be parsed
```
+38915424
```

- A sorted list of version and file name (for a time machine-like use) 
- and, by default, 'deduplicated' in file names (future: file size too)
- version_number
- datetime (or D for deleted)
- size (with dots)
- filename or ? (if not changed from previous)

### Example (two record)
_The file f:/zarc/ihsv/pakka/30_3/zpaqfranz.exe is 3.089.462 bytes long,
and was found in the 946 version, @ 02/10/2020 14:25:34  (European-style date format)  
In the version 959 the file result deleted (not present)_
```
-946
02/10/2020 14:25:34
3.089.462
f:/zarc/ihsv/pakka/30_3/zpaqfranz.exe
-959
D
0
?
```

### Optional switches

```
-pakka for more verbose
-distinct do not 'deduplicate'
-all show all versions
-key password
-until version
-out logfile.txt
```
# How to compile (Windows)
_Nothing hard_

```
g++ -O3  zpaqlist.cpp -o zpaqlist -static  
```
