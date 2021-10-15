/*
                                                              

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

*/

#define ZPAQLIST_VERSION "franz24"

#define _FILE_OFFSET_BITS 64  
#define UNICODE

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <vector>
#include <map>
#include <fcntl.h>



namespace libzpaq {

// 1, 2, 4, 8 byte unsigned integers
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;

// Tables for parsing ZPAQL source code
extern const char* compname[256];    // list of ZPAQL component types
extern const int compsize[256];      // number of bytes to encode a component
extern const char* opcodelist[272];  // list of ZPAQL instructions

// Callback for error handling
extern void error(const char* msg);

// Virtual base classes for input and output
// get() and put() must be overridden to read or write 1 byte.
// read() and write() may be overridden to read or write n bytes more
// efficiently than calling get() or put() n times.
class Reader {
public:
  virtual int get() = 0;  // should return 0..255, or -1 at EOF
  virtual int read(char* buf, int n); // read to buf[n], return no. read
  virtual ~Reader() {}
};

class Writer {
public:
  virtual void put(int c) = 0;  // should output low 8 bits of c
  virtual void write(const char* buf, int n);  // write buf[n]
  virtual ~Writer() {}
};

// Read 16 bit little-endian number
int toU16(const char* p);

// An Array of T is cleared and aligned on a 64 byte address
//   with no constructors called. No copy or assignment.
// Array<T> a(n, ex=0);  - creates n<<ex elements of type T
// a[i] - index
// a(i) - index mod n, n must be a power of 2
// a.size() - gets n
template <typename T>
class Array {
  T *data;     // user location of [0] on a 64 byte boundary
  size_t n;    // user size
  int offset;  // distance back in bytes to start of actual allocation
  void operator=(const Array&);  // no assignment
  Array(const Array&);  // no copy
public:
  Array(size_t sz=0, int ex=0): data(0), n(0), offset(0) {
    resize(sz, ex);} // [0..sz-1] = 0
  void resize(size_t sz, int ex=0); // change size, erase content to zeros
  ~Array() {resize(0);}  // free memory
  size_t size() const {return n;}  // get size
  int isize() const {return int(n);}  // get size as an int
  T& operator[](size_t i) {return data[i];}
  T& operator()(size_t i) {return data[i&(n-1)];}
};

// Change size to sz<<ex elements of 0
template<typename T>
void Array<T>::resize(size_t sz, int ex) {
  while (ex>0) {
    if (sz>sz*2) error("Array too big");
    sz*=2, --ex;
  }
  if (n>0) {
    ::free((char*)data-offset);
  }
  n=0;
  if (sz==0) return;
  n=sz;
  const size_t nb=128+n*sizeof(T);  // test for overflow
  if (nb<=128 || (nb-128)/sizeof(T)!=n) error("Array too big");
  data=(T*)::calloc(nb, 1);
  if (!data) n=0, error("Out of memory");
  offset=64-(((char*)data-(char*)0)&63);
  data=(T*)((char*)data+offset);
}

//////////////////////////// SHA1 ////////////////////////////

// For computing SHA-1 checksums
class SHA1 {
public:
  void put(int c) {  // hash 1 byte
    U32& r=w[len0>>5&15];
    r=(r<<8)|(c&255);
    if (!(len0+=8)) ++len1;
    if ((len0&511)==0) process();
  }
  double size() const {return len0/8+len1*536870912.0;} // size in bytes
  uint64_t usize() const {return len0/8+(U64(len1)<<29);} // size in bytes
  const char* result();  // get hash and reset
  SHA1() {init();}
private:
  void init();      // reset, but don't clear hbuf
  U32 len0, len1;   // length in bits (low, high)
  U32 h[5];         // hash state
  U32 w[16];        // input buffer
  char hbuf[20];    // result
  void process();   // hash 1 block
};

//////////////////////////// SHA256 //////////////////////////

// For computing SHA-256 checksums
// http://en.wikipedia.org/wiki/SHA-2
class SHA256 {
public:
  void put(int c) {  // hash 1 byte
    unsigned& r=w[len0>>5&15];
    r=(r<<8)|(c&255);
    if (!(len0+=8)) ++len1;
    if ((len0&511)==0) process();
  }
  double size() const {return len0/8+len1*536870912.0;} // size in bytes
  uint64_t usize() const {return len0/8+(U64(len1)<<29);} //size in bytes
  const char* result();  // get hash and reset
  SHA256() {init();}
private:
  void init();           // reset, but don't clear hbuf
  unsigned len0, len1;   // length in bits (low, high)
  unsigned s[8];         // hash state
  unsigned w[16];        // input buffer
  char hbuf[32];         // result
  void process();        // hash 1 block
};

//////////////////////////// AES /////////////////////////////

// For encrypting with AES in CTR mode.
// The i'th 16 byte block is encrypted by XOR with AES(i)
// (i is big endian or MSB first, starting with 0).
class AES_CTR {
  U32 Te0[256], Te1[256], Te2[256], Te3[256], Te4[256]; // encryption tables
  U32 ek[60];  // round key
  int Nr;  // number of rounds (10, 12, 14 for AES 128, 192, 256)
  U32 iv0, iv1;  // first 8 bytes in CTR mode
public:
  AES_CTR(const char* key, int keylen, const char* iv=0);
    // Schedule: keylen is 16, 24, or 32, iv is 8 bytes or NULL
  void encrypt(U32 s0, U32 s1, U32 s2, U32 s3, unsigned char* ct);
  void encrypt(char* buf, int n, U64 offset);  // encrypt n bytes of buf
};

//////////////////////////// stretchKey //////////////////////

// Strengthen password pw[0..pwlen-1] and salt[0..saltlen-1]
// to produce key buf[0..buflen-1]. Uses O(n*r*p) time and 128*r*n bytes
// of memory. n must be a power of 2 and r <= 8.
void scrypt(const char* pw, int pwlen,
            const char* salt, int saltlen,
            int n, int r, int p, char* buf, int buflen);

// Generate a strong key out[0..31] key[0..31] and salt[0..31].
// Calls scrypt(key, 32, salt, 32, 16384, 8, 1, out, 32);
void stretchKey(char* out, const char* key, const char* salt);

//////////////////////////// ZPAQL ///////////////////////////

// Symbolic constants, instruction size, and names
typedef enum {NONE,CONS,CM,ICM,MATCH,AVG,MIX2,MIX,ISSE,SSE} CompType;
extern const int compsize[256];

// A ZPAQL machine COMP+HCOMP or PCOMP.
class ZPAQL {
public:
  ZPAQL();
  ~ZPAQL();
  void clear();           // Free memory, erase program, reset machine state
  void inith();           // Initialize as HCOMP to run
  void initp();           // Initialize as PCOMP to run
  double memory();        // Return memory requirement in bytes
  void run(U32 input);    // Execute with input
  int read(Reader* in2);  // Read header
  bool write(Writer* out2, bool pp); // If pp write PCOMP else HCOMP header
  int step(U32 input, int mode);  // Trace execution (defined externally)

  Writer* output;         // Destination for OUT instruction, or 0 to suppress
  SHA1* sha1;             // Points to checksum computer
  U32 H(int i) {return h(i);}  // get element of h

  void flush();           // write outbuf[0..bufptr-1] to output and sha1
  void outc(int c) {      // output byte c (0..255) or -1 at EOS
    if (c<0 || (outbuf[bufptr]=c, ++bufptr==outbuf.isize())) flush();
  }

  // ZPAQ1 block header
  Array<U8> header;   // hsize[2] hh hm ph pm n COMP (guard) HCOMP (guard)
  int cend;           // COMP in header[7...cend-1]
  int hbegin, hend;   // HCOMP/PCOMP in header[hbegin...hend-1]

private:
  // Machine state for executing HCOMP
  Array<U8> m;        // memory array M for HCOMP
  Array<U32> h;       // hash array H for HCOMP
  Array<U32> r;       // 256 element register array
  Array<char> outbuf; // output buffer
  int bufptr;         // number of bytes in outbuf
  U32 a, b, c, d;     // machine registers
  int f;              // condition flag
  int pc;             // program counter
  int rcode_size;     // length of rcode
  U8* rcode;          // JIT code for run()

  // Support code
  int assemble();  // put JIT code in rcode
  void init(int hbits, int mbits);  // initialize H and M sizes
  int execute();  // interpret 1 instruction, return 0 after HALT, else 1
  void run0(U32 input);  // default run() if not JIT
  void div(U32 x) {if (x) a/=x; else a=0;}
  void mod(U32 x) {if (x) a%=x; else a=0;}
  void swap(U32& x) {a^=x; x^=a; a^=x;}
  void swap(U8& x)  {a^=x; x^=a; a^=x;}
  void err();  // exit with run time error
};

///////////////////////// Component //////////////////////////

// A Component is a context model, indirect context model, match model,
// fixed weight mixer, adaptive 2 input mixer without or with current
// partial byte as context, adaptive m input mixer (without or with),
// or SSE (without or with).

struct Component {
  size_t limit;   // max count for cm
  size_t cxt;     // saved context
  size_t a, b, c; // multi-purpose variables
  Array<U32> cm;  // cm[cxt] -> p in bits 31..10, n in 9..0; MATCH index
  Array<U8> ht;   // ICM/ISSE hash table[0..size1][0..15] and MATCH buf
  Array<U16> a16; // MIX weights
  void init();    // initialize to all 0
  Component() {init();}
};

////////////////////////// StateTable ////////////////////////

// Next state table
class StateTable {
public:
  U8 ns[1024]; // state*4 -> next state if 0, if 1, n0, n1
  int next(int state, int y) {  // next state for bit y
    return ns[state*4+y];
  }
  int cminit(int state) {  // initial probability of 1 * 2^23
    return ((ns[state*4+3]*2+1)<<22)/(ns[state*4+2]+ns[state*4+3]+1);
  }
  StateTable();
};

///////////////////////// Predictor //////////////////////////

// A predictor guesses the next bit
class Predictor {
public:
  Predictor(ZPAQL&);
  ~Predictor();
  void init();          // build model
  int predict();        // probability that next bit is a 1 (0..4095)
  void update(int y);   // train on bit y (0..1)
  int stat(int);        // Defined externally
  bool isModeled() {    // n>0 components?
    return z.header[6]!=0;
  }
private:

  // Predictor state
  int c8;               // last 0...7 bits.
  int hmap4;            // c8 split into nibbles
  int p[256];           // predictions
  U32 h[256];           // unrolled copy of z.h
  ZPAQL& z;             // VM to compute context hashes, includes H, n
  Component comp[256];  // the model, includes P

  // Modeling support functions
  int predict0();       // default
  void update0(int y);  // default
  int dt2k[256];        // division table for match: dt2k[i] = 2^12/i
  int dt[1024];         // division table for cm: dt[i] = 2^16/(i+1.5)
  U16 squasht[4096];    // squash() lookup table
  short stretcht[32768];// stretch() lookup table
  StateTable st;        // next, cminit functions
  U8* pcode;            // JIT code for predict() and update()
  int pcode_size;       // length of pcode

  // reduce prediction error in cr.cm
  void train(Component& cr, int y) {
 
    U32& pn=cr.cm(cr.cxt);
    U32 count=pn&0x3ff;
    int error=y*32767-(cr.cm(cr.cxt)>>17);
    pn+=(error*dt[count]&-1024)+(count<cr.limit);
  }

  // x -> floor(32768/(1+exp(-x/64)))
  int squash(int x) {

    return squasht[x+2048];
  }

  // x -> round(64*log((x+0.5)/(32767.5-x))), approx inverse of squash
  int stretch(int x) {

    return stretcht[x];
  }

  // bound x to a 12 bit signed int
  int clamp2k(int x) {
    if (x<-2048) return -2048;
    else if (x>2047) return 2047;
    else return x;
  }

  // bound x to a 20 bit signed int
  int clamp512k(int x) {
    if (x<-(1<<19)) return -(1<<19);
    else if (x>=(1<<19)) return (1<<19)-1;
    else return x;
  }

  // Get cxt in ht, creating a new row if needed
  size_t find(Array<U8>& ht, int sizebits, U32 cxt);

  // Put JIT code in pcode
  int assemble_p();
};

//////////////////////////// Decoder /////////////////////////

// Decoder decompresses using an arithmetic code
class Decoder {
public:
  Reader* in;        // destination
  Decoder(ZPAQL& z);
  int decompress();  // return a byte or EOF
  int skip();        // skip to the end of the segment, return next byte
  void init();       // initialize at start of block
  int stat(int x) {return pr.stat(x);}
private:
  U32 low, high;     // range
  U32 curr;          // last 4 bytes of archive
  Predictor pr;      // to get p
  enum {BUFSIZE=1<<16};
  Array<char> buf;   // input buffer of size BUFSIZE bytes
    // of unmodeled data. buf[low..high-1] is input with curr
    // remaining in sub-block.
  int decode(int p); // return decoded bit (0..1) with prob. p (0..65535)
  void loadbuf();    // read unmodeled data into buf to EOS
};

/////////////////////////// PostProcessor ////////////////////

class PostProcessor {
  int state;   // input parse state: 0=INIT, 1=PASS, 2..4=loading, 5=POST
  int hsize;   // header size
  int ph, pm;  // sizes of H and M in z
public:
  ZPAQL z;     // holds PCOMP
  PostProcessor(): state(0), hsize(0), ph(0), pm(0) {}
  void init(int h, int m);  // ph, pm sizes of H and M
  int write(int c);  // Input a byte, return state
  int getState() const {return state;}
  void setOutput(Writer* out) {z.output=out;}
  void setSHA1(SHA1* sha1ptr) {z.sha1=sha1ptr;}
};

//////////////////////// Decompresser ////////////////////////

// For decompression and listing archive contents
class Decompresser {
public:
  Decompresser(): z(), dec(z), pp(), state(BLOCK), decode_state(FIRSTSEG) {}
  void setInput(Reader* in) {dec.in=in;}
  bool findBlock(double* memptr = 0);
  void hcomp(Writer* out2) {z.write(out2, false);}
  bool findFilename(Writer* = 0);
  void readComment(Writer* = 0);
  void setOutput(Writer* out) {pp.setOutput(out);}
  void setSHA1(SHA1* sha1ptr) {pp.setSHA1(sha1ptr);}
  bool decompress(int n = -1);  // n bytes, -1=all, return true until done
  bool pcomp(Writer* out2) {return pp.z.write(out2, true);}
  void readSegmentEnd(char* sha1string = 0);
  int stat(int x) {return dec.stat(x);}
private:
  ZPAQL z;
  Decoder dec;
  PostProcessor pp;
  enum {BLOCK, FILENAME, COMMENT, DATA, SEGEND} state;  // expected next
  enum {FIRSTSEG, SEG, SKIP} decode_state;  // which segment in block?
};

/////////////////////////// decompress() /////////////////////

void decompress(Reader* in, Writer* out);

//////////////////////////// Encoder /////////////////////////

// Encoder compresses using an arithmetic code
class Encoder {
public:
  Encoder(ZPAQL& z):
    out(0), low(1), high(0xFFFFFFFF), pr(z) {}
  void init();
  void compress(int c);  // c is 0..255 or EOF
  int stat(int x) {return pr.stat(x);}
  Writer* out;  // destination
private:
  U32 low, high; // range
  Predictor pr;  // to get p
  Array<char> buf; // unmodeled input
  void encode(int y, int p); // encode bit y (0..1) with prob. p (0..65535)
};

//////////////////////////// Compiler ////////////////////////

// Input ZPAQL source code with args and store the compiled code
// in hz and pz and write pcomp_cmd to out2.

class Compiler {
public:
  Compiler(const char* in, int* args, ZPAQL& hz, ZPAQL& pz, Writer* out2);
private:
  const char* in;  // ZPAQL source code
  int* args;       // Array of up to 9 args, default NULL = all 0
  ZPAQL& hz;       // Output of COMP and HCOMP sections
  ZPAQL& pz;       // Output of PCOMP section
  Writer* out2;    // Output ... of "PCOMP ... ;"
  int line;        // Input line number for reporting errors
  int state;       // parse state: 0=space -1=word >0 (nest level)

  // Symbolic constants
  typedef enum {NONE,CONS,CM,ICM,MATCH,AVG,MIX2,MIX,ISSE,SSE,
    JT=39,JF=47,JMP=63,LJ=255,
    POST=256,PCOMP,END,IF,IFNOT,ELSE,ENDIF,DO,
    WHILE,UNTIL,FOREVER,IFL,IFNOTL,ELSEL,SEMICOLON} CompType;

  void syntaxError(const char* msg, const char* expected=0); // error()
  void next();                     // advance in to next token
  bool matchToken(const char* tok);// in==token?
  int rtoken(int low, int high);   // return token which must be in range
  int rtoken(const char* list[]);  // return token by position in list
  void rtoken(const char* s);      // return token which must be s
  int compile_comp(ZPAQL& z);      // compile either HCOMP or PCOMP

  // Stack of n elements
  class Stack {
    libzpaq::Array<U16> s;
    size_t top;
  public:
    Stack(int n): s(n), top(0) {}
    void push(const U16& x) {
      if (top>=s.size()) error("IF or DO nested too deep");
      s[top++]=x;
    }
    U16 pop() {
      if (top<=0) error("unmatched IF or DO");
      return s[--top];
    }
  };

  Stack if_stack, do_stack;
};


// Read 16 bit little-endian number
int toU16(const char* p) {
  return (p[0]&255)+256*(p[1]&255);
}

// Default read() and write()
int Reader::read(char* buf, int n) {
  int i=0, c;
  while (i<n && (c=get())>=0)
    buf[i++]=c;
  return i;
}

void Writer::write(const char* buf, int n) {
  for (int i=0; i<n; ++i)
    put(U8(buf[i]));
}

///////////////////////// allocx //////////////////////

// Allocate newsize > 0 bytes of executable memory and update
// p to point to it and newsize = n. Free any previously
// allocated memory first. If newsize is 0 then free only.
// Call error in case of failure. If NOJIT, ignore newsize
// and set p=0, n=0 without allocating memory.
void allocx(U8* &p, int &n, int newsize) {
#ifdef NOJIT
  p=0;
  n=0;
#else
  if (p || n) {
    if (p)
#ifdef unix
      munmap(p, n);
#else // Windows
      VirtualFree(p, 0, MEM_RELEASE);
#endif
    p=0;
    n=0;
  }
  if (newsize>0) {
#ifdef unix
    p=(U8*)mmap(0, newsize, PROT_READ|PROT_WRITE|PROT_EXEC,
                MAP_PRIVATE|MAP_ANON, -1, 0);
    if ((void*)p==MAP_FAILED) p=0;
#else
    p=(U8*)VirtualAlloc(0, newsize, MEM_RESERVE|MEM_COMMIT,
                        PAGE_EXECUTE_READWRITE);
#endif
    if (p)
      n=newsize;
    else {
      n=0;
      error("allocx failed");
    }
  }
#endif
}

//////////////////////////// SHA1 ////////////////////////////

// SHA1 code, see http://en.wikipedia.org/wiki/SHA-1

// Start a new hash
void SHA1::init() {
  len0=len1=0;
  h[0]=0x67452301;
  h[1]=0xEFCDAB89;
  h[2]=0x98BADCFE;
  h[3]=0x10325476;
  h[4]=0xC3D2E1F0;
  memset(w, 0, sizeof(w));
}

// Return old result and start a new hash
const char* SHA1::result() {

  // pad and append length
  const U32 s1=len1, s0=len0;
  put(0x80);
  while ((len0&511)!=448)
    put(0);
  put(s1>>24);
  put(s1>>16);
  put(s1>>8);
  put(s1);
  put(s0>>24);
  put(s0>>16);
  put(s0>>8);
  put(s0);

  // copy h to hbuf
  for (int i=0; i<5; ++i) {
    hbuf[4*i]=h[i]>>24;
    hbuf[4*i+1]=h[i]>>16;
    hbuf[4*i+2]=h[i]>>8;
    hbuf[4*i+3]=h[i];
  }

  // return hash prior to clearing state
  init();
  return hbuf;
}


// Hash 1 block of 64 bytes
void SHA1::process() {
  U32 a=h[0], b=h[1], c=h[2], d=h[3], e=h[4];
  static const U32 k[4]={0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  #define f(a,b,c,d,e,i) \
    if (i>=16) \
      w[(i)&15]^=w[(i-3)&15]^w[(i-8)&15]^w[(i-14)&15], \
      w[(i)&15]=w[(i)&15]<<1|w[(i)&15]>>31; \
    e+=(a<<5|a>>27)+k[(i)/20]+w[(i)&15] \
      +((i)%40>=20 ? b^c^d : i>=40 ? (b&c)|(d&(b|c)) : d^(b&(c^d))); \
    b=b<<30|b>>2;
  #define r(i) f(a,b,c,d,e,i) f(e,a,b,c,d,i+1) f(d,e,a,b,c,i+2) \
               f(c,d,e,a,b,i+3) f(b,c,d,e,a,i+4)
  r(0)  r(5)  r(10) r(15) r(20) r(25) r(30) r(35)
  r(40) r(45) r(50) r(55) r(60) r(65) r(70) r(75)
  #undef f
  #undef r
  h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
}

//////////////////////////// SHA256 //////////////////////////

void SHA256::init() {
  len0=len1=0;
  s[0]=0x6a09e667;
  s[1]=0xbb67ae85;
  s[2]=0x3c6ef372;
  s[3]=0xa54ff53a;
  s[4]=0x510e527f;
  s[5]=0x9b05688c;
  s[6]=0x1f83d9ab;
  s[7]=0x5be0cd19;
  memset(w, 0, sizeof(w));
}

void SHA256::process() {

  #define ror(a,b) ((a)>>(b)|(a<<(32-(b))))

  #define m(i) \
     w[(i)&15]+=w[(i-7)&15] \
       +(ror(w[(i-15)&15],7)^ror(w[(i-15)&15],18)^(w[(i-15)&15]>>3)) \
       +(ror(w[(i-2)&15],17)^ror(w[(i-2)&15],19)^(w[(i-2)&15]>>10))

  #define r(a,b,c,d,e,f,g,h,i) { \
    unsigned t1=ror(e,14)^e; \
    t1=ror(t1,5)^e; \
    h+=ror(t1,6)+((e&f)^(~e&g))+k[i]+w[(i)&15]; } \
    d+=h; \
    {unsigned t1=ror(a,9)^a; \
    t1=ror(t1,11)^a; \
    h+=ror(t1,2)+((a&b)^(c&(a^b))); }

  #define mr(a,b,c,d,e,f,g,h,i) m(i); r(a,b,c,d,e,f,g,h,i);

  #define r8(i) \
    r(a,b,c,d,e,f,g,h,i);   \
    r(h,a,b,c,d,e,f,g,i+1); \
    r(g,h,a,b,c,d,e,f,i+2); \
    r(f,g,h,a,b,c,d,e,i+3); \
    r(e,f,g,h,a,b,c,d,i+4); \
    r(d,e,f,g,h,a,b,c,i+5); \
    r(c,d,e,f,g,h,a,b,i+6); \
    r(b,c,d,e,f,g,h,a,i+7);

  #define mr8(i) \
    mr(a,b,c,d,e,f,g,h,i);   \
    mr(h,a,b,c,d,e,f,g,i+1); \
    mr(g,h,a,b,c,d,e,f,i+2); \
    mr(f,g,h,a,b,c,d,e,i+3); \
    mr(e,f,g,h,a,b,c,d,i+4); \
    mr(d,e,f,g,h,a,b,c,i+5); \
    mr(c,d,e,f,g,h,a,b,i+6); \
    mr(b,c,d,e,f,g,h,a,i+7);

  static const unsigned k[64]={
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  unsigned a=s[0];
  unsigned b=s[1];
  unsigned c=s[2];
  unsigned d=s[3];
  unsigned e=s[4];
  unsigned f=s[5];
  unsigned g=s[6];
  unsigned h=s[7];

  r8(0);
  r8(8);
  mr8(16);
  mr8(24);
  mr8(32);
  mr8(40);
  mr8(48);
  mr8(56);

  s[0]+=a;
  s[1]+=b;
  s[2]+=c;
  s[3]+=d;
  s[4]+=e;
  s[5]+=f;
  s[6]+=g;
  s[7]+=h;

  #undef mr8
  #undef r8
  #undef mr
  #undef r
  #undef m
  #undef ror
}

// Return old result and start a new hash
const char* SHA256::result() {

  // pad and append length
  const unsigned s1=len1, s0=len0;
  put(0x80);
  while ((len0&511)!=448) put(0);
  put(s1>>24);
  put(s1>>16);
  put(s1>>8);
  put(s1);
  put(s0>>24);
  put(s0>>16);
  put(s0>>8);
  put(s0);

  // copy s to hbuf
  for (int i=0; i<8; ++i) {
    hbuf[4*i]=s[i]>>24;
    hbuf[4*i+1]=s[i]>>16;
    hbuf[4*i+2]=s[i]>>8;
    hbuf[4*i+3]=s[i];
  }

  // return hash prior to clearing state
  init();
  return hbuf;
}

//////////////////////////// AES /////////////////////////////

// Some AES code is derived from libtomcrypt 1.17 (public domain).

#define Te4_0 0x000000FF & Te4
#define Te4_1 0x0000FF00 & Te4
#define Te4_2 0x00FF0000 & Te4
#define Te4_3 0xFF000000 & Te4

// Extract byte n of x
static inline unsigned byte(unsigned x, unsigned n) {return (x>>(8*n))&255;}

// x = y[0..3] MSB first
static inline void LOAD32H(U32& x, const char* y) {
  const unsigned char* u=(const unsigned char*)y;
  x=u[0]<<24|u[1]<<16|u[2]<<8|u[3];
}

// y[0..3] = x MSB first
static inline void STORE32H(U32& x, unsigned char* y) {
  y[0]=x>>24;
  y[1]=x>>16;
  y[2]=x>>8;
  y[3]=x;
}

#define setup_mix(temp) \
  ((Te4_3[byte(temp, 2)]) ^ (Te4_2[byte(temp, 1)]) ^ \
   (Te4_1[byte(temp, 0)]) ^ (Te4_0[byte(temp, 3)]))

// Initialize encryption tables and round key. keylen is 16, 24, or 32.
AES_CTR::AES_CTR(const char* key, int keylen, const char* iv) {
 

  // Initialize IV (default 0)
  iv0=iv1=0;
  if (iv) {
    LOAD32H(iv0, iv);
    LOAD32H(iv1, iv+4);
  }

  // Initialize encryption tables
  for (int i=0; i<256; ++i) {
    unsigned s1=
    "\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
    "\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0"
    "\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15"
    "\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75"
    "\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84"
    "\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf"
    "\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8"
    "\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2"
    "\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73"
    "\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb"
    "\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79"
    "\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08"
    "\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a"
    "\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e"
    "\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf"
    "\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16"
    [i]&255;
    unsigned s2=s1<<1;
    if (s2>=0x100) s2^=0x11b;
    unsigned s3=s1^s2;
    Te0[i]=s2<<24|s1<<16|s1<<8|s3;
    Te1[i]=s3<<24|s2<<16|s1<<8|s1;
    Te2[i]=s1<<24|s3<<16|s2<<8|s1;
    Te3[i]=s1<<24|s1<<16|s3<<8|s2;
    Te4[i]=s1<<24|s1<<16|s1<<8|s1;
  }

  // setup the forward key
  Nr = 10 + ((keylen/8)-2)*2;  // 10, 12, or 14 rounds
  int i = 0;
  U32* rk = &ek[0];
  U32 temp;
  static const U32 rcon[10] = {
    0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL,
    0x10000000UL, 0x20000000UL, 0x40000000UL, 0x80000000UL,
    0x1B000000UL, 0x36000000UL};  // round constants

  LOAD32H(rk[0], key   );
  LOAD32H(rk[1], key +  4);
  LOAD32H(rk[2], key +  8);
  LOAD32H(rk[3], key + 12);
  if (keylen == 16) {
    for (;;) {
      temp  = rk[3];
      rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
      rk[5] = rk[1] ^ rk[4];
      rk[6] = rk[2] ^ rk[5];
      rk[7] = rk[3] ^ rk[6];
      if (++i == 10) {
         break;
      }
      rk += 4;
    }
  }
  else if (keylen == 24) {
    LOAD32H(rk[4], key + 16);
    LOAD32H(rk[5], key + 20);
    for (;;) {
      temp = rk[5];
      rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
      rk[ 7] = rk[ 1] ^ rk[ 6];
      rk[ 8] = rk[ 2] ^ rk[ 7];
      rk[ 9] = rk[ 3] ^ rk[ 8];
      if (++i == 8) {
        break;
      }
      rk[10] = rk[ 4] ^ rk[ 9];
      rk[11] = rk[ 5] ^ rk[10];
      rk += 6;
    }
  }
  else if (keylen == 32) {
    LOAD32H(rk[4], key + 16);
    LOAD32H(rk[5], key + 20);
    LOAD32H(rk[6], key + 24);
    LOAD32H(rk[7], key + 28);
    for (;;) {
      temp = rk[7];
      rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
      rk[ 9] = rk[ 1] ^ rk[ 8];
      rk[10] = rk[ 2] ^ rk[ 9];
      rk[11] = rk[ 3] ^ rk[10];
      if (++i == 7) {
        break;
      }
      temp = rk[11];
      rk[12] = rk[ 4] ^ setup_mix(temp<<24|temp>>8);
      rk[13] = rk[ 5] ^ rk[12];
      rk[14] = rk[ 6] ^ rk[13];
      rk[15] = rk[ 7] ^ rk[14];
      rk += 8;
    }
  }
}

// Encrypt to ct[16]
void AES_CTR::encrypt(U32 s0, U32 s1, U32 s2, U32 s3, unsigned char* ct) {
  int r = Nr >> 1;
  U32 *rk = &ek[0];
  U32 t0=0, t1=0, t2=0, t3=0;
  s0 ^= rk[0];
  s1 ^= rk[1];
  s2 ^= rk[2];
  s3 ^= rk[3];
  for (;;) {
    t0 =
      Te0[byte(s0, 3)] ^
      Te1[byte(s1, 2)] ^
      Te2[byte(s2, 1)] ^
      Te3[byte(s3, 0)] ^
      rk[4];
    t1 =
      Te0[byte(s1, 3)] ^
      Te1[byte(s2, 2)] ^
      Te2[byte(s3, 1)] ^
      Te3[byte(s0, 0)] ^
      rk[5];
    t2 =
      Te0[byte(s2, 3)] ^
      Te1[byte(s3, 2)] ^
      Te2[byte(s0, 1)] ^
      Te3[byte(s1, 0)] ^
      rk[6];
    t3 =
      Te0[byte(s3, 3)] ^
      Te1[byte(s0, 2)] ^
      Te2[byte(s1, 1)] ^
      Te3[byte(s2, 0)] ^
      rk[7];

    rk += 8;
    if (--r == 0) {
      break;
    }

    s0 =
      Te0[byte(t0, 3)] ^
      Te1[byte(t1, 2)] ^
      Te2[byte(t2, 1)] ^
      Te3[byte(t3, 0)] ^
      rk[0];
    s1 =
      Te0[byte(t1, 3)] ^
      Te1[byte(t2, 2)] ^
      Te2[byte(t3, 1)] ^
      Te3[byte(t0, 0)] ^
      rk[1];
    s2 =
      Te0[byte(t2, 3)] ^
      Te1[byte(t3, 2)] ^
      Te2[byte(t0, 1)] ^
      Te3[byte(t1, 0)] ^
      rk[2];
    s3 =
      Te0[byte(t3, 3)] ^
      Te1[byte(t0, 2)] ^
      Te2[byte(t1, 1)] ^
      Te3[byte(t2, 0)] ^
      rk[3];
  }

  // apply last round and map cipher state to byte array block:
  s0 =
    (Te4_3[byte(t0, 3)]) ^
    (Te4_2[byte(t1, 2)]) ^
    (Te4_1[byte(t2, 1)]) ^
    (Te4_0[byte(t3, 0)]) ^
    rk[0];
  STORE32H(s0, ct);
  s1 =
    (Te4_3[byte(t1, 3)]) ^
    (Te4_2[byte(t2, 2)]) ^
    (Te4_1[byte(t3, 1)]) ^
    (Te4_0[byte(t0, 0)]) ^
    rk[1];
  STORE32H(s1, ct+4);
  s2 =
    (Te4_3[byte(t2, 3)]) ^
    (Te4_2[byte(t3, 2)]) ^
    (Te4_1[byte(t0, 1)]) ^
    (Te4_0[byte(t1, 0)]) ^
    rk[2];
  STORE32H(s2, ct+8);
  s3 =
    (Te4_3[byte(t3, 3)]) ^
    (Te4_2[byte(t0, 2)]) ^
    (Te4_1[byte(t1, 1)]) ^
    (Te4_0[byte(t2, 0)]) ^ 
    rk[3];
  STORE32H(s3, ct+12);
}

// Encrypt or decrypt slice buf[0..n-1] at offset by XOR with AES(i) where
// i is the 128 bit big-endian distance from the start in 16 byte blocks.
void AES_CTR::encrypt(char* buf, int n, U64 offset) {
  for (U64 i=offset/16; i<=(offset+n)/16; ++i) {
    unsigned char ct[16];
    encrypt(iv0, iv1, i>>32, i, ct);
    for (int j=0; j<16; ++j) {
      const int k=i*16-offset+j;
      if (k>=0 && k<n)
        buf[k]^=ct[j];
    }
  }
}

#undef setup_mix
#undef Te4_3
#undef Te4_2
#undef Te4_1
#undef Te4_0

//////////////////////////// stretchKey //////////////////////

// PBKDF2(pw[0..pwlen], salt[0..saltlen], c) to buf[0..dkLen-1]
// using HMAC-SHA256, for the special case of c = 1 iterations
// output size dkLen a multiple of 32, and pwLen <= 64.
static void pbkdf2(const char* pw, int pwLen, const char* salt, int saltLen,
                    char* buf, int dkLen) {
 

  libzpaq::SHA256 sha256;
  char b[32];
  for (int i=1; i*32<=dkLen; ++i) {
    for (int j=0; j<pwLen; ++j) sha256.put(pw[j]^0x36);
    for (int j=pwLen; j<64; ++j) sha256.put(0x36);
    for (int j=0; j<saltLen; ++j) sha256.put(salt[j]);
    for (int j=24; j>=0; j-=8) sha256.put(i>>j);
    memcpy(b, sha256.result(), 32);
    for (int j=0; j<pwLen; ++j) sha256.put(pw[j]^0x5c);
    for (int j=pwLen; j<64; ++j) sha256.put(0x5c);
    for (int j=0; j<32; ++j) sha256.put(b[j]);
    memcpy(buf+i*32-32, sha256.result(), 32);
  }
}

// Hash b[0..15] using 8 rounds of salsa20
// Modified from http://cr.yp.to/salsa20.html (public domain) to 8 rounds
static void salsa8(U32* b) {
  unsigned x[16]={0};
  memcpy(x, b, 64);
  for (int i=0; i<4; ++i) {
    #define R(a,b) (((a)<<(b))+((a)>>(32-b)))
    x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
    x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
    x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
    x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
    x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
    x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
    x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
    x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
    x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
    x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
    x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
    x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
    x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
    x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
    x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
    x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
    #undef R
  }
  for (int i=0; i<16; ++i) b[i]+=x[i];
}

// BlockMix_{Salsa20/8, r} on b[0..128*r-1]
static void blockmix(U32* b, int r) {
 
  U32 x[16];
  U32 y[256];
  memcpy(x, b+32*r-16, 64);
  for (int i=0; i<2*r; ++i) {
    for (int j=0; j<16; ++j) x[j]^=b[i*16+j];
    salsa8(x);
    memcpy(&y[i*16], x, 64);
  }
  for (int i=0; i<r; ++i) memcpy(b+i*16, &y[i*32], 64);
  for (int i=0; i<r; ++i) memcpy(b+(i+r)*16, &y[i*32+16], 64);
}

// Mix b[0..128*r-1]. Uses 128*r*n bytes of memory and O(r*n) time
static void smix(char* b, int r, int n) {
  libzpaq::Array<U32> x(32*r), v(32*r*n);
  for (int i=0; i<r*128; ++i) x[i/4]+=(b[i]&255)<<i%4*8;
  for (int i=0; i<n; ++i) {
    memcpy(&v[i*r*32], &x[0], r*128);
    blockmix(&x[0], r);
  }
  for (int i=0; i<n; ++i) {
    U32 j=x[(2*r-1)*16]&(n-1);
    for (int k=0; k<r*32; ++k) x[k]^=v[j*r*32+k];
    blockmix(&x[0], r);
  }
  for (int i=0; i<r*128; ++i) b[i]=x[i/4]>>(i%4*8);
}

// Strengthen password pw[0..pwlen-1] and salt[0..saltlen-1]
// to produce key buf[0..buflen-1]. Uses O(n*r*p) time and 128*r*n bytes
// of memory. n must be a power of 2 and r <= 8.
void scrypt(const char* pw, int pwlen,
            const char* salt, int saltlen,
            int n, int r, int p, char* buf, int buflen) {
 
  libzpaq::Array<char> b(p*r*128);
  pbkdf2(pw, pwlen, salt, saltlen,  &b[0], p*r*128);
  for (int i=0; i<p; ++i) smix(&b[i*r*128], r, n);
  pbkdf2(pw, pwlen, &b[0], p*r*128,  buf, buflen);
}

// Stretch key in[0..31], assumed to be SHA256(password), with
// NUL terminate salt to produce new key out[0..31]
void stretchKey(char* out, const char* in, const char* salt) {
  scrypt(in, 32, salt, 32, 1<<14, 8, 1, out, 32);
}

//////////////////////////// Component ///////////////////////

// A Component is a context model, indirect context model, match model,
// fixed weight mixer, adaptive 2 input mixer without or with current
// partial byte as context, adaptive m input mixer (without or with),
// or SSE (without or with).

const int compsize[256]={0,2,3,2,3,4,6,6,3,5};

void Component::init() {
  limit=cxt=a=b=c=0;
  cm.resize(0);
  ht.resize(0);
  a16.resize(0);
}

////////////////////////// StateTable ////////////////////////

// sns[i*4] -> next state if 0, next state if 1, n0, n1
static const U8 sns[1024]={
     1,     2,     0,     0,     3,     5,     1,     0,
     4,     6,     0,     1,     7,     9,     2,     0,
     8,    11,     1,     1,     8,    11,     1,     1,
    10,    12,     0,     2,    13,    15,     3,     0,
    14,    17,     2,     1,    14,    17,     2,     1,
    16,    19,     1,     2,    16,    19,     1,     2,
    18,    20,     0,     3,    21,    23,     4,     0,
    22,    25,     3,     1,    22,    25,     3,     1,
    24,    27,     2,     2,    24,    27,     2,     2,
    26,    29,     1,     3,    26,    29,     1,     3,
    28,    30,     0,     4,    31,    33,     5,     0,
    32,    35,     4,     1,    32,    35,     4,     1,
    34,    37,     3,     2,    34,    37,     3,     2,
    36,    39,     2,     3,    36,    39,     2,     3,
    38,    41,     1,     4,    38,    41,     1,     4,
    40,    42,     0,     5,    43,    33,     6,     0,
    44,    47,     5,     1,    44,    47,     5,     1,
    46,    49,     4,     2,    46,    49,     4,     2,
    48,    51,     3,     3,    48,    51,     3,     3,
    50,    53,     2,     4,    50,    53,     2,     4,
    52,    55,     1,     5,    52,    55,     1,     5,
    40,    56,     0,     6,    57,    45,     7,     0,
    58,    47,     6,     1,    58,    47,     6,     1,
    60,    63,     5,     2,    60,    63,     5,     2,
    62,    65,     4,     3,    62,    65,     4,     3,
    64,    67,     3,     4,    64,    67,     3,     4,
    66,    69,     2,     5,    66,    69,     2,     5,
    52,    71,     1,     6,    52,    71,     1,     6,
    54,    72,     0,     7,    73,    59,     8,     0,
    74,    61,     7,     1,    74,    61,     7,     1,
    76,    63,     6,     2,    76,    63,     6,     2,
    78,    81,     5,     3,    78,    81,     5,     3,
    80,    83,     4,     4,    80,    83,     4,     4,
    82,    85,     3,     5,    82,    85,     3,     5,
    66,    87,     2,     6,    66,    87,     2,     6,
    68,    89,     1,     7,    68,    89,     1,     7,
    70,    90,     0,     8,    91,    59,     9,     0,
    92,    77,     8,     1,    92,    77,     8,     1,
    94,    79,     7,     2,    94,    79,     7,     2,
    96,    81,     6,     3,    96,    81,     6,     3,
    98,   101,     5,     4,    98,   101,     5,     4,
   100,   103,     4,     5,   100,   103,     4,     5,
    82,   105,     3,     6,    82,   105,     3,     6,
    84,   107,     2,     7,    84,   107,     2,     7,
    86,   109,     1,     8,    86,   109,     1,     8,
    70,   110,     0,     9,   111,    59,    10,     0,
   112,    77,     9,     1,   112,    77,     9,     1,
   114,    97,     8,     2,   114,    97,     8,     2,
   116,    99,     7,     3,   116,    99,     7,     3,
    62,   101,     6,     4,    62,   101,     6,     4,
    80,    83,     5,     5,    80,    83,     5,     5,
   100,    67,     4,     6,   100,    67,     4,     6,
   102,   119,     3,     7,   102,   119,     3,     7,
   104,   121,     2,     8,   104,   121,     2,     8,
    86,   123,     1,     9,    86,   123,     1,     9,
    70,   124,     0,    10,   125,    59,    11,     0,
   126,    77,    10,     1,   126,    77,    10,     1,
   128,    97,     9,     2,   128,    97,     9,     2,
    60,    63,     8,     3,    60,    63,     8,     3,
    66,    69,     3,     8,    66,    69,     3,     8,
   104,   131,     2,     9,   104,   131,     2,     9,
    86,   133,     1,    10,    86,   133,     1,    10,
    70,   134,     0,    11,   135,    59,    12,     0,
   136,    77,    11,     1,   136,    77,    11,     1,
   138,    97,    10,     2,   138,    97,    10,     2,
   104,   141,     2,    10,   104,   141,     2,    10,
    86,   143,     1,    11,    86,   143,     1,    11,
    70,   144,     0,    12,   145,    59,    13,     0,
   146,    77,    12,     1,   146,    77,    12,     1,
   148,    97,    11,     2,   148,    97,    11,     2,
   104,   151,     2,    11,   104,   151,     2,    11,
    86,   153,     1,    12,    86,   153,     1,    12,
    70,   154,     0,    13,   155,    59,    14,     0,
   156,    77,    13,     1,   156,    77,    13,     1,
   158,    97,    12,     2,   158,    97,    12,     2,
   104,   161,     2,    12,   104,   161,     2,    12,
    86,   163,     1,    13,    86,   163,     1,    13,
    70,   164,     0,    14,   165,    59,    15,     0,
   166,    77,    14,     1,   166,    77,    14,     1,
   168,    97,    13,     2,   168,    97,    13,     2,
   104,   171,     2,    13,   104,   171,     2,    13,
    86,   173,     1,    14,    86,   173,     1,    14,
    70,   174,     0,    15,   175,    59,    16,     0,
   176,    77,    15,     1,   176,    77,    15,     1,
   178,    97,    14,     2,   178,    97,    14,     2,
   104,   181,     2,    14,   104,   181,     2,    14,
    86,   183,     1,    15,    86,   183,     1,    15,
    70,   184,     0,    16,   185,    59,    17,     0,
   186,    77,    16,     1,   186,    77,    16,     1,
    74,    97,    15,     2,    74,    97,    15,     2,
   104,    89,     2,    15,   104,    89,     2,    15,
    86,   187,     1,    16,    86,   187,     1,    16,
    70,   188,     0,    17,   189,    59,    18,     0,
   190,    77,    17,     1,    86,   191,     1,    17,
    70,   192,     0,    18,   193,    59,    19,     0,
   194,    77,    18,     1,    86,   195,     1,    18,
    70,   196,     0,    19,   193,    59,    20,     0,
   197,    77,    19,     1,    86,   198,     1,    19,
    70,   196,     0,    20,   199,    77,    20,     1,
    86,   200,     1,    20,   201,    77,    21,     1,
    86,   202,     1,    21,   203,    77,    22,     1,
    86,   204,     1,    22,   205,    77,    23,     1,
    86,   206,     1,    23,   207,    77,    24,     1,
    86,   208,     1,    24,   209,    77,    25,     1,
    86,   210,     1,    25,   211,    77,    26,     1,
    86,   212,     1,    26,   213,    77,    27,     1,
    86,   214,     1,    27,   215,    77,    28,     1,
    86,   216,     1,    28,   217,    77,    29,     1,
    86,   218,     1,    29,   219,    77,    30,     1,
    86,   220,     1,    30,   221,    77,    31,     1,
    86,   222,     1,    31,   223,    77,    32,     1,
    86,   224,     1,    32,   225,    77,    33,     1,
    86,   226,     1,    33,   227,    77,    34,     1,
    86,   228,     1,    34,   229,    77,    35,     1,
    86,   230,     1,    35,   231,    77,    36,     1,
    86,   232,     1,    36,   233,    77,    37,     1,
    86,   234,     1,    37,   235,    77,    38,     1,
    86,   236,     1,    38,   237,    77,    39,     1,
    86,   238,     1,    39,   239,    77,    40,     1,
    86,   240,     1,    40,   241,    77,    41,     1,
    86,   242,     1,    41,   243,    77,    42,     1,
    86,   244,     1,    42,   245,    77,    43,     1,
    86,   246,     1,    43,   247,    77,    44,     1,
    86,   248,     1,    44,   249,    77,    45,     1,
    86,   250,     1,    45,   251,    77,    46,     1,
    86,   252,     1,    46,   253,    77,    47,     1,
    86,   254,     1,    47,   253,    77,    48,     1,
    86,   254,     1,    48,     0,     0,     0,     0
};

// Initialize next state table ns[state*4] -> next if 0, next if 1, n0, n1
StateTable::StateTable() {
  memcpy(ns, sns, sizeof(ns));
}

/////////////////////////// ZPAQL //////////////////////////

// Write header to out2, return true if HCOMP/PCOMP section is present.
// If pp is true, then write only the postprocessor code.

// Read header from in2
int ZPAQL::read(Reader* in2) {

  // Get header size and allocate
  int hsize=in2->get();
  hsize+=in2->get()*256;
  header.resize(hsize+300);
  cend=hbegin=hend=0;
  header[cend++]=hsize&255;
  header[cend++]=hsize>>8;
  while (cend<7) header[cend++]=in2->get(); // hh hm ph pm n

  // Read COMP
  int n=header[cend-1];
  for (int i=0; i<n; ++i) {
    int type=in2->get();  // component type
    if (type==-1) error("unexpected end of file");
    header[cend++]=type;  // component type
    int size=compsize[type];
    if (size<1) error("Invalid component type");
    if (cend+size>header.isize()-8) error("COMP list too big");
    for (int j=1; j<size; ++j)
      header[cend++]=in2->get();
  }
  if ((header[cend++]=in2->get())!=0) error("missing COMP END");

  // Insert a guard gap and read HCOMP
  hbegin=hend=cend+128;
  while (hend<hsize+129) {
  
    int op=in2->get();
    if (op==-1) error("unexpected end of file");
    header[hend++]=op;
  }
  if ((header[hend++]=in2->get())!=0) error("missing HCOMP END");

  allocx(rcode, rcode_size, 0);  // clear JIT code
  return cend+hend-hbegin;
}

// Free memory, but preserve output, sha1 pointers
void ZPAQL::clear() {
  cend=hbegin=hend=0;  // COMP and HCOMP locations
  a=b=c=d=f=pc=0;      // machine state
  header.resize(0);
  h.resize(0);
  m.resize(0);
  r.resize(0);
  allocx(rcode, rcode_size, 0);
}

// Constructor
ZPAQL::ZPAQL() {
  output=0;
  sha1=0;
  rcode=0;
  rcode_size=0;
  clear();
  outbuf.resize(1<<14);
  bufptr=0;
}

ZPAQL::~ZPAQL() {
  allocx(rcode, rcode_size, 0);
}

// Initialize machine state as HCOMP
void ZPAQL::inith() {

  init(header[2], header[3]); // hh, hm
}

// Initialize machine state as PCOMP
void ZPAQL::initp() {
 
  init(header[4], header[5]); // ph, pm
}

// Flush pending output
void ZPAQL::flush() {
  if (output) output->write(&outbuf[0], bufptr);
  if (sha1) for (int i=0; i<bufptr; ++i) sha1->put(U8(outbuf[i]));
  bufptr=0;
}

// pow(2, x)
static double pow2(int x) {
  double r=1;
  for (; x>0; x--) r+=r;
  return r;
}

// Return memory requirement in bytes
double ZPAQL::memory() {
  double mem=pow2(header[2]+2)+pow2(header[3])  // hh hm
            +pow2(header[4]+2)+pow2(header[5])  // ph pm
            +header.size();
  int cp=7;  // start of comp list
  for (int i=0; i<header[6]; ++i) {  // n
  
    double size=pow2(header[cp+1]); // sizebits
    switch(header[cp]) {
      case CM: mem+=4*size; break;
      case ICM: mem+=64*size+1024; break;
      case MATCH: mem+=4*size+pow2(header[cp+2]); break; // bufbits
      case MIX2: mem+=2*size; break;
      case MIX: mem+=4*size*header[cp+3]; break; // m
      case ISSE: mem+=64*size+2048; break;
      case SSE: mem+=128*size; break;
    }
    cp+=compsize[header[cp]];
  }
  return mem;
}

// Initialize machine state to run a program.
void ZPAQL::init(int hbits, int mbits) {
 
  h.resize(1, hbits);
  m.resize(1, mbits);
  r.resize(256);
  a=b=c=d=pc=f=0;
}

// Run program on input by interpreting header
void ZPAQL::run0(U32 input) {
 
  pc=hbegin;
  a=input;
  while (execute()) ;
}

// Execute one instruction, return 0 after HALT else 1
int ZPAQL::execute() {
  switch(header[pc++]) {
    case 0: err(); break; // ERROR
    case 1: ++a; break; // A++
    case 2: --a; break; // A--
    case 3: a = ~a; break; // A!
    case 4: a = 0; break; // A=0
    case 7: a = r[header[pc++]]; break; // A=R N
    case 8: swap(b); break; // B<>A
    case 9: ++b; break; // B++
    case 10: --b; break; // B--
    case 11: b = ~b; break; // B!
    case 12: b = 0; break; // B=0
    case 15: b = r[header[pc++]]; break; // B=R N
    case 16: swap(c); break; // C<>A
    case 17: ++c; break; // C++
    case 18: --c; break; // C--
    case 19: c = ~c; break; // C!
    case 20: c = 0; break; // C=0
    case 23: c = r[header[pc++]]; break; // C=R N
    case 24: swap(d); break; // D<>A
    case 25: ++d; break; // D++
    case 26: --d; break; // D--
    case 27: d = ~d; break; // D!
    case 28: d = 0; break; // D=0
    case 31: d = r[header[pc++]]; break; // D=R N
    case 32: swap(m(b)); break; // *B<>A
    case 33: ++m(b); break; // *B++
    case 34: --m(b); break; // *B--
    case 35: m(b) = ~m(b); break; // *B!
    case 36: m(b) = 0; break; // *B=0
    case 39: if (f) pc+=((header[pc]+128)&255)-127; else ++pc; break; // JT N
    case 40: swap(m(c)); break; // *C<>A
    case 41: ++m(c); break; // *C++
    case 42: --m(c); break; // *C--
    case 43: m(c) = ~m(c); break; // *C!
    case 44: m(c) = 0; break; // *C=0
    case 47: if (!f) pc+=((header[pc]+128)&255)-127; else ++pc; break; // JF N
    case 48: swap(h(d)); break; // *D<>A
    case 49: ++h(d); break; // *D++
    case 50: --h(d); break; // *D--
    case 51: h(d) = ~h(d); break; // *D!
    case 52: h(d) = 0; break; // *D=0
    case 55: r[header[pc++]] = a; break; // R=A N
    case 56: return 0  ; // HALT
    case 57: outc(a&255); break; // OUT
    case 59: a = (a+m(b)+512)*773; break; // HASH
    case 60: h(d) = (h(d)+a+512)*773; break; // HASHD
    case 63: pc+=((header[pc]+128)&255)-127; break; // JMP N
    case 64: break; // A=A
    case 65: a = b; break; // A=B
    case 66: a = c; break; // A=C
    case 67: a = d; break; // A=D
    case 68: a = m(b); break; // A=*B
    case 69: a = m(c); break; // A=*C
    case 70: a = h(d); break; // A=*D
    case 71: a = header[pc++]; break; // A= N
    case 72: b = a; break; // B=A
    case 73: break; // B=B
    case 74: b = c; break; // B=C
    case 75: b = d; break; // B=D
    case 76: b = m(b); break; // B=*B
    case 77: b = m(c); break; // B=*C
    case 78: b = h(d); break; // B=*D
    case 79: b = header[pc++]; break; // B= N
    case 80: c = a; break; // C=A
    case 81: c = b; break; // C=B
    case 82: break; // C=C
    case 83: c = d; break; // C=D
    case 84: c = m(b); break; // C=*B
    case 85: c = m(c); break; // C=*C
    case 86: c = h(d); break; // C=*D
    case 87: c = header[pc++]; break; // C= N
    case 88: d = a; break; // D=A
    case 89: d = b; break; // D=B
    case 90: d = c; break; // D=C
    case 91: break; // D=D
    case 92: d = m(b); break; // D=*B
    case 93: d = m(c); break; // D=*C
    case 94: d = h(d); break; // D=*D
    case 95: d = header[pc++]; break; // D= N
    case 96: m(b) = a; break; // *B=A
    case 97: m(b) = b; break; // *B=B
    case 98: m(b) = c; break; // *B=C
    case 99: m(b) = d; break; // *B=D
    case 100: m(b) = m(b); break; // *B=*B
    case 101: m(b) = m(c); break; // *B=*C
    case 102: m(b) = h(d); break; // *B=*D
    case 103: m(b) = header[pc++]; break; // *B= N
    case 104: m(c) = a; break; // *C=A
    case 105: m(c) = b; break; // *C=B
    case 106: m(c) = c; break; // *C=C
    case 107: m(c) = d; break; // *C=D
    case 108: m(c) = m(b); break; // *C=*B
    case 109: m(c) = m(c); break; // *C=*C
    case 110: m(c) = h(d); break; // *C=*D
    case 111: m(c) = header[pc++]; break; // *C= N
    case 112: h(d) = a; break; // *D=A
    case 113: h(d) = b; break; // *D=B
    case 114: h(d) = c; break; // *D=C
    case 115: h(d) = d; break; // *D=D
    case 116: h(d) = m(b); break; // *D=*B
    case 117: h(d) = m(c); break; // *D=*C
    case 118: h(d) = h(d); break; // *D=*D
    case 119: h(d) = header[pc++]; break; // *D= N
    case 128: a += a; break; // A+=A
    case 129: a += b; break; // A+=B
    case 130: a += c; break; // A+=C
    case 131: a += d; break; // A+=D
    case 132: a += m(b); break; // A+=*B
    case 133: a += m(c); break; // A+=*C
    case 134: a += h(d); break; // A+=*D
    case 135: a += header[pc++]; break; // A+= N
    case 136: a -= a; break; // A-=A
    case 137: a -= b; break; // A-=B
    case 138: a -= c; break; // A-=C
    case 139: a -= d; break; // A-=D
    case 140: a -= m(b); break; // A-=*B
    case 141: a -= m(c); break; // A-=*C
    case 142: a -= h(d); break; // A-=*D
    case 143: a -= header[pc++]; break; // A-= N
    case 144: a *= a; break; // A*=A
    case 145: a *= b; break; // A*=B
    case 146: a *= c; break; // A*=C
    case 147: a *= d; break; // A*=D
    case 148: a *= m(b); break; // A*=*B
    case 149: a *= m(c); break; // A*=*C
    case 150: a *= h(d); break; // A*=*D
    case 151: a *= header[pc++]; break; // A*= N
    case 152: div(a); break; // A/=A
    case 153: div(b); break; // A/=B
    case 154: div(c); break; // A/=C
    case 155: div(d); break; // A/=D
    case 156: div(m(b)); break; // A/=*B
    case 157: div(m(c)); break; // A/=*C
    case 158: div(h(d)); break; // A/=*D
    case 159: div(header[pc++]); break; // A/= N
    case 160: mod(a); break; // A%=A
    case 161: mod(b); break; // A%=B
    case 162: mod(c); break; // A%=C
    case 163: mod(d); break; // A%=D
    case 164: mod(m(b)); break; // A%=*B
    case 165: mod(m(c)); break; // A%=*C
    case 166: mod(h(d)); break; // A%=*D
    case 167: mod(header[pc++]); break; // A%= N
    case 168: a &= a; break; // A&=A
    case 169: a &= b; break; // A&=B
    case 170: a &= c; break; // A&=C
    case 171: a &= d; break; // A&=D
    case 172: a &= m(b); break; // A&=*B
    case 173: a &= m(c); break; // A&=*C
    case 174: a &= h(d); break; // A&=*D
    case 175: a &= header[pc++]; break; // A&= N
    case 176: a &= ~ a; break; // A&~A
    case 177: a &= ~ b; break; // A&~B
    case 178: a &= ~ c; break; // A&~C
    case 179: a &= ~ d; break; // A&~D
    case 180: a &= ~ m(b); break; // A&~*B
    case 181: a &= ~ m(c); break; // A&~*C
    case 182: a &= ~ h(d); break; // A&~*D
    case 183: a &= ~ header[pc++]; break; // A&~ N
    case 184: a |= a; break; // A|=A
    case 185: a |= b; break; // A|=B
    case 186: a |= c; break; // A|=C
    case 187: a |= d; break; // A|=D
    case 188: a |= m(b); break; // A|=*B
    case 189: a |= m(c); break; // A|=*C
    case 190: a |= h(d); break; // A|=*D
    case 191: a |= header[pc++]; break; // A|= N
    case 192: a ^= a; break; // A^=A
    case 193: a ^= b; break; // A^=B
    case 194: a ^= c; break; // A^=C
    case 195: a ^= d; break; // A^=D
    case 196: a ^= m(b); break; // A^=*B
    case 197: a ^= m(c); break; // A^=*C
    case 198: a ^= h(d); break; // A^=*D
    case 199: a ^= header[pc++]; break; // A^= N
    case 200: a <<= (a&31); break; // A<<=A
    case 201: a <<= (b&31); break; // A<<=B
    case 202: a <<= (c&31); break; // A<<=C
    case 203: a <<= (d&31); break; // A<<=D
    case 204: a <<= (m(b)&31); break; // A<<=*B
    case 205: a <<= (m(c)&31); break; // A<<=*C
    case 206: a <<= (h(d)&31); break; // A<<=*D
    case 207: a <<= (header[pc++]&31); break; // A<<= N
    case 208: a >>= (a&31); break; // A>>=A
    case 209: a >>= (b&31); break; // A>>=B
    case 210: a >>= (c&31); break; // A>>=C
    case 211: a >>= (d&31); break; // A>>=D
    case 212: a >>= (m(b)&31); break; // A>>=*B
    case 213: a >>= (m(c)&31); break; // A>>=*C
    case 214: a >>= (h(d)&31); break; // A>>=*D
    case 215: a >>= (header[pc++]&31); break; // A>>= N
    case 216: f = 1; break; // A==A
    case 217: f = (a == b); break; // A==B
    case 218: f = (a == c); break; // A==C
    case 219: f = (a == d); break; // A==D
    case 220: f = (a == U32(m(b))); break; // A==*B
    case 221: f = (a == U32(m(c))); break; // A==*C
    case 222: f = (a == h(d)); break; // A==*D
    case 223: f = (a == U32(header[pc++])); break; // A== N
    case 224: f = 0; break; // A<A
    case 225: f = (a < b); break; // A<B
    case 226: f = (a < c); break; // A<C
    case 227: f = (a < d); break; // A<D
    case 228: f = (a < U32(m(b))); break; // A<*B
    case 229: f = (a < U32(m(c))); break; // A<*C
    case 230: f = (a < h(d)); break; // A<*D
    case 231: f = (a < U32(header[pc++])); break; // A< N
    case 232: f = 0; break; // A>A
    case 233: f = (a > b); break; // A>B
    case 234: f = (a > c); break; // A>C
    case 235: f = (a > d); break; // A>D
    case 236: f = (a > U32(m(b))); break; // A>*B
    case 237: f = (a > U32(m(c))); break; // A>*C
    case 238: f = (a > h(d)); break; // A>*D
    case 239: f = (a > U32(header[pc++])); break; // A> N
    case 255: if((pc=hbegin+header[pc]+256*header[pc+1])>=hend)err();break;//LJ
    default: err();
  }
  return 1;
}

// Print illegal instruction error message and exit
void ZPAQL::err() {
  error("ZPAQL execution error");
}

///////////////////////// Predictor /////////////////////////

// sdt2k[i]=2048/i;
static const int sdt2k[256]={
     0,  2048,  1024,   682,   512,   409,   341,   292,
   256,   227,   204,   186,   170,   157,   146,   136,
   128,   120,   113,   107,   102,    97,    93,    89,
    85,    81,    78,    75,    73,    70,    68,    66,
    64,    62,    60,    58,    56,    55,    53,    52,
    51,    49,    48,    47,    46,    45,    44,    43,
    42,    41,    40,    40,    39,    38,    37,    37,
    36,    35,    35,    34,    34,    33,    33,    32,
    32,    31,    31,    30,    30,    29,    29,    28,
    28,    28,    27,    27,    26,    26,    26,    25,
    25,    25,    24,    24,    24,    24,    23,    23,
    23,    23,    22,    22,    22,    22,    21,    21,
    21,    21,    20,    20,    20,    20,    20,    19,
    19,    19,    19,    19,    18,    18,    18,    18,
    18,    18,    17,    17,    17,    17,    17,    17,
    17,    16,    16,    16,    16,    16,    16,    16,
    16,    15,    15,    15,    15,    15,    15,    15,
    15,    14,    14,    14,    14,    14,    14,    14,
    14,    14,    14,    13,    13,    13,    13,    13,
    13,    13,    13,    13,    13,    13,    12,    12,
    12,    12,    12,    12,    12,    12,    12,    12,
    12,    12,    12,    11,    11,    11,    11,    11,
    11,    11,    11,    11,    11,    11,    11,    11,
    11,    11,    11,    10,    10,    10,    10,    10,
    10,    10,    10,    10,    10,    10,    10,    10,
    10,    10,    10,    10,    10,     9,     9,     9,
     9,     9,     9,     9,     9,     9,     9,     9,
     9,     9,     9,     9,     9,     9,     9,     9,
     9,     9,     9,     9,     8,     8,     8,     8,
     8,     8,     8,     8,     8,     8,     8,     8,
     8,     8,     8,     8,     8,     8,     8,     8,
     8,     8,     8,     8,     8,     8,     8,     8
};

// sdt[i]=(1<<17)/(i*2+3)*2;
static const int sdt[1024]={
 87380, 52428, 37448, 29126, 23830, 20164, 17476, 15420,
 13796, 12482, 11396, 10484,  9708,  9038,  8456,  7942,
  7488,  7084,  6720,  6392,  6096,  5824,  5576,  5348,
  5140,  4946,  4766,  4598,  4442,  4296,  4160,  4032,
  3912,  3798,  3692,  3590,  3494,  3404,  3318,  3236,
  3158,  3084,  3012,  2944,  2880,  2818,  2758,  2702,
  2646,  2594,  2544,  2496,  2448,  2404,  2360,  2318,
  2278,  2240,  2202,  2166,  2130,  2096,  2064,  2032,
  2000,  1970,  1940,  1912,  1884,  1858,  1832,  1806,
  1782,  1758,  1736,  1712,  1690,  1668,  1648,  1628,
  1608,  1588,  1568,  1550,  1532,  1514,  1496,  1480,
  1464,  1448,  1432,  1416,  1400,  1386,  1372,  1358,
  1344,  1330,  1316,  1304,  1290,  1278,  1266,  1254,
  1242,  1230,  1218,  1208,  1196,  1186,  1174,  1164,
  1154,  1144,  1134,  1124,  1114,  1106,  1096,  1086,
  1078,  1068,  1060,  1052,  1044,  1036,  1028,  1020,
  1012,  1004,   996,   988,   980,   974,   966,   960,
   952,   946,   938,   932,   926,   918,   912,   906,
   900,   894,   888,   882,   876,   870,   864,   858,
   852,   848,   842,   836,   832,   826,   820,   816,
   810,   806,   800,   796,   790,   786,   782,   776,
   772,   768,   764,   758,   754,   750,   746,   742,
   738,   734,   730,   726,   722,   718,   714,   710,
   706,   702,   698,   694,   690,   688,   684,   680,
   676,   672,   670,   666,   662,   660,   656,   652,
   650,   646,   644,   640,   636,   634,   630,   628,
   624,   622,   618,   616,   612,   610,   608,   604,
   602,   598,   596,   594,   590,   588,   586,   582,
   580,   578,   576,   572,   570,   568,   566,   562,
   560,   558,   556,   554,   550,   548,   546,   544,
   542,   540,   538,   536,   532,   530,   528,   526,
   524,   522,   520,   518,   516,   514,   512,   510,
   508,   506,   504,   502,   500,   498,   496,   494,
   492,   490,   488,   488,   486,   484,   482,   480,
   478,   476,   474,   474,   472,   470,   468,   466,
   464,   462,   462,   460,   458,   456,   454,   454,
   452,   450,   448,   448,   446,   444,   442,   442,
   440,   438,   436,   436,   434,   432,   430,   430,
   428,   426,   426,   424,   422,   422,   420,   418,
   418,   416,   414,   414,   412,   410,   410,   408,
   406,   406,   404,   402,   402,   400,   400,   398,
   396,   396,   394,   394,   392,   390,   390,   388,
   388,   386,   386,   384,   382,   382,   380,   380,
   378,   378,   376,   376,   374,   372,   372,   370,
   370,   368,   368,   366,   366,   364,   364,   362,
   362,   360,   360,   358,   358,   356,   356,   354,
   354,   352,   352,   350,   350,   348,   348,   348,
   346,   346,   344,   344,   342,   342,   340,   340,
   340,   338,   338,   336,   336,   334,   334,   332,
   332,   332,   330,   330,   328,   328,   328,   326,
   326,   324,   324,   324,   322,   322,   320,   320,
   320,   318,   318,   316,   316,   316,   314,   314,
   312,   312,   312,   310,   310,   310,   308,   308,
   308,   306,   306,   304,   304,   304,   302,   302,
   302,   300,   300,   300,   298,   298,   298,   296,
   296,   296,   294,   294,   294,   292,   292,   292,
   290,   290,   290,   288,   288,   288,   286,   286,
   286,   284,   284,   284,   284,   282,   282,   282,
   280,   280,   280,   278,   278,   278,   276,   276,
   276,   276,   274,   274,   274,   272,   272,   272,
   272,   270,   270,   270,   268,   268,   268,   268,
   266,   266,   266,   266,   264,   264,   264,   262,
   262,   262,   262,   260,   260,   260,   260,   258,
   258,   258,   258,   256,   256,   256,   256,   254,
   254,   254,   254,   252,   252,   252,   252,   250,
   250,   250,   250,   248,   248,   248,   248,   248,
   246,   246,   246,   246,   244,   244,   244,   244,
   242,   242,   242,   242,   242,   240,   240,   240,
   240,   238,   238,   238,   238,   238,   236,   236,
   236,   236,   234,   234,   234,   234,   234,   232,
   232,   232,   232,   232,   230,   230,   230,   230,
   230,   228,   228,   228,   228,   228,   226,   226,
   226,   226,   226,   224,   224,   224,   224,   224,
   222,   222,   222,   222,   222,   220,   220,   220,
   220,   220,   220,   218,   218,   218,   218,   218,
   216,   216,   216,   216,   216,   216,   214,   214,
   214,   214,   214,   212,   212,   212,   212,   212,
   212,   210,   210,   210,   210,   210,   210,   208,
   208,   208,   208,   208,   208,   206,   206,   206,
   206,   206,   206,   204,   204,   204,   204,   204,
   204,   204,   202,   202,   202,   202,   202,   202,
   200,   200,   200,   200,   200,   200,   198,   198,
   198,   198,   198,   198,   198,   196,   196,   196,
   196,   196,   196,   196,   194,   194,   194,   194,
   194,   194,   194,   192,   192,   192,   192,   192,
   192,   192,   190,   190,   190,   190,   190,   190,
   190,   188,   188,   188,   188,   188,   188,   188,
   186,   186,   186,   186,   186,   186,   186,   186,
   184,   184,   184,   184,   184,   184,   184,   182,
   182,   182,   182,   182,   182,   182,   182,   180,
   180,   180,   180,   180,   180,   180,   180,   178,
   178,   178,   178,   178,   178,   178,   178,   176,
   176,   176,   176,   176,   176,   176,   176,   176,
   174,   174,   174,   174,   174,   174,   174,   174,
   172,   172,   172,   172,   172,   172,   172,   172,
   172,   170,   170,   170,   170,   170,   170,   170,
   170,   170,   168,   168,   168,   168,   168,   168,
   168,   168,   168,   166,   166,   166,   166,   166,
   166,   166,   166,   166,   166,   164,   164,   164,
   164,   164,   164,   164,   164,   164,   162,   162,
   162,   162,   162,   162,   162,   162,   162,   162,
   160,   160,   160,   160,   160,   160,   160,   160,
   160,   160,   158,   158,   158,   158,   158,   158,
   158,   158,   158,   158,   158,   156,   156,   156,
   156,   156,   156,   156,   156,   156,   156,   154,
   154,   154,   154,   154,   154,   154,   154,   154,
   154,   154,   152,   152,   152,   152,   152,   152,
   152,   152,   152,   152,   152,   150,   150,   150,
   150,   150,   150,   150,   150,   150,   150,   150,
   150,   148,   148,   148,   148,   148,   148,   148,
   148,   148,   148,   148,   148,   146,   146,   146,
   146,   146,   146,   146,   146,   146,   146,   146,
   146,   144,   144,   144,   144,   144,   144,   144,
   144,   144,   144,   144,   144,   142,   142,   142,
   142,   142,   142,   142,   142,   142,   142,   142,
   142,   142,   140,   140,   140,   140,   140,   140,
   140,   140,   140,   140,   140,   140,   140,   138,
   138,   138,   138,   138,   138,   138,   138,   138,
   138,   138,   138,   138,   138,   136,   136,   136,
   136,   136,   136,   136,   136,   136,   136,   136,
   136,   136,   136,   134,   134,   134,   134,   134,
   134,   134,   134,   134,   134,   134,   134,   134,
   134,   132,   132,   132,   132,   132,   132,   132,
   132,   132,   132,   132,   132,   132,   132,   132,
   130,   130,   130,   130,   130,   130,   130,   130,
   130,   130,   130,   130,   130,   130,   130,   128,
   128,   128,   128,   128,   128,   128,   128,   128,
   128,   128,   128,   128,   128,   128,   128,   126
};

// ssquasht[i]=int(32768.0/(1+exp((i-2048)*(-1.0/64))));
// Middle 1344 of 4096 entries only.
static const U16 ssquasht[1344]={
     0,     0,     0,     0,     0,     0,     0,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,
     4,     4,     4,     4,     4,     4,     4,     4,
     4,     4,     4,     4,     4,     4,     5,     5,
     5,     5,     5,     5,     5,     5,     5,     5,
     5,     5,     6,     6,     6,     6,     6,     6,
     6,     6,     6,     6,     7,     7,     7,     7,
     7,     7,     7,     7,     8,     8,     8,     8,
     8,     8,     8,     8,     9,     9,     9,     9,
     9,     9,    10,    10,    10,    10,    10,    10,
    10,    11,    11,    11,    11,    11,    12,    12,
    12,    12,    12,    13,    13,    13,    13,    13,
    14,    14,    14,    14,    15,    15,    15,    15,
    15,    16,    16,    16,    17,    17,    17,    17,
    18,    18,    18,    18,    19,    19,    19,    20,
    20,    20,    21,    21,    21,    22,    22,    22,
    23,    23,    23,    24,    24,    25,    25,    25,
    26,    26,    27,    27,    28,    28,    28,    29,
    29,    30,    30,    31,    31,    32,    32,    33,
    33,    34,    34,    35,    36,    36,    37,    37,
    38,    38,    39,    40,    40,    41,    42,    42,
    43,    44,    44,    45,    46,    46,    47,    48,
    49,    49,    50,    51,    52,    53,    54,    54,
    55,    56,    57,    58,    59,    60,    61,    62,
    63,    64,    65,    66,    67,    68,    69,    70,
    71,    72,    73,    74,    76,    77,    78,    79,
    81,    82,    83,    84,    86,    87,    88,    90,
    91,    93,    94,    96,    97,    99,   100,   102,
   103,   105,   107,   108,   110,   112,   114,   115,
   117,   119,   121,   123,   125,   127,   129,   131,
   133,   135,   137,   139,   141,   144,   146,   148,
   151,   153,   155,   158,   160,   163,   165,   168,
   171,   173,   176,   179,   182,   184,   187,   190,
   193,   196,   199,   202,   206,   209,   212,   215,
   219,   222,   226,   229,   233,   237,   240,   244,
   248,   252,   256,   260,   264,   268,   272,   276,
   281,   285,   289,   294,   299,   303,   308,   313,
   318,   323,   328,   333,   338,   343,   349,   354,
   360,   365,   371,   377,   382,   388,   394,   401,
   407,   413,   420,   426,   433,   440,   446,   453,
   460,   467,   475,   482,   490,   497,   505,   513,
   521,   529,   537,   545,   554,   562,   571,   580,
   589,   598,   607,   617,   626,   636,   646,   656,
   666,   676,   686,   697,   708,   719,   730,   741,
   752,   764,   776,   788,   800,   812,   825,   837,
   850,   863,   876,   890,   903,   917,   931,   946,
   960,   975,   990,  1005,  1020,  1036,  1051,  1067,
  1084,  1100,  1117,  1134,  1151,  1169,  1186,  1204,
  1223,  1241,  1260,  1279,  1298,  1318,  1338,  1358,
  1379,  1399,  1421,  1442,  1464,  1486,  1508,  1531,
  1554,  1577,  1600,  1624,  1649,  1673,  1698,  1724,
  1749,  1775,  1802,  1829,  1856,  1883,  1911,  1940,
  1968,  1998,  2027,  2057,  2087,  2118,  2149,  2181,
  2213,  2245,  2278,  2312,  2345,  2380,  2414,  2450,
  2485,  2521,  2558,  2595,  2633,  2671,  2709,  2748,
  2788,  2828,  2869,  2910,  2952,  2994,  3037,  3080,
  3124,  3168,  3213,  3259,  3305,  3352,  3399,  3447,
  3496,  3545,  3594,  3645,  3696,  3747,  3799,  3852,
  3906,  3960,  4014,  4070,  4126,  4182,  4240,  4298,
  4356,  4416,  4476,  4537,  4598,  4660,  4723,  4786,
  4851,  4916,  4981,  5048,  5115,  5183,  5251,  5320,
  5390,  5461,  5533,  5605,  5678,  5752,  5826,  5901,
  5977,  6054,  6131,  6210,  6289,  6369,  6449,  6530,
  6613,  6695,  6779,  6863,  6949,  7035,  7121,  7209,
  7297,  7386,  7476,  7566,  7658,  7750,  7842,  7936,
  8030,  8126,  8221,  8318,  8415,  8513,  8612,  8712,
  8812,  8913,  9015,  9117,  9221,  9324,  9429,  9534,
  9640,  9747,  9854,  9962, 10071, 10180, 10290, 10401,
 10512, 10624, 10737, 10850, 10963, 11078, 11192, 11308,
 11424, 11540, 11658, 11775, 11893, 12012, 12131, 12251,
 12371, 12491, 12612, 12734, 12856, 12978, 13101, 13224,
 13347, 13471, 13595, 13719, 13844, 13969, 14095, 14220,
 14346, 14472, 14599, 14725, 14852, 14979, 15106, 15233,
 15361, 15488, 15616, 15744, 15872, 16000, 16128, 16256,
 16384, 16511, 16639, 16767, 16895, 17023, 17151, 17279,
 17406, 17534, 17661, 17788, 17915, 18042, 18168, 18295,
 18421, 18547, 18672, 18798, 18923, 19048, 19172, 19296,
 19420, 19543, 19666, 19789, 19911, 20033, 20155, 20276,
 20396, 20516, 20636, 20755, 20874, 20992, 21109, 21227,
 21343, 21459, 21575, 21689, 21804, 21917, 22030, 22143,
 22255, 22366, 22477, 22587, 22696, 22805, 22913, 23020,
 23127, 23233, 23338, 23443, 23546, 23650, 23752, 23854,
 23955, 24055, 24155, 24254, 24352, 24449, 24546, 24641,
 24737, 24831, 24925, 25017, 25109, 25201, 25291, 25381,
 25470, 25558, 25646, 25732, 25818, 25904, 25988, 26072,
 26154, 26237, 26318, 26398, 26478, 26557, 26636, 26713,
 26790, 26866, 26941, 27015, 27089, 27162, 27234, 27306,
 27377, 27447, 27516, 27584, 27652, 27719, 27786, 27851,
 27916, 27981, 28044, 28107, 28169, 28230, 28291, 28351,
 28411, 28469, 28527, 28585, 28641, 28697, 28753, 28807,
 28861, 28915, 28968, 29020, 29071, 29122, 29173, 29222,
 29271, 29320, 29368, 29415, 29462, 29508, 29554, 29599,
 29643, 29687, 29730, 29773, 29815, 29857, 29898, 29939,
 29979, 30019, 30058, 30096, 30134, 30172, 30209, 30246,
 30282, 30317, 30353, 30387, 30422, 30455, 30489, 30522,
 30554, 30586, 30618, 30649, 30680, 30710, 30740, 30769,
 30799, 30827, 30856, 30884, 30911, 30938, 30965, 30992,
 31018, 31043, 31069, 31094, 31118, 31143, 31167, 31190,
 31213, 31236, 31259, 31281, 31303, 31325, 31346, 31368,
 31388, 31409, 31429, 31449, 31469, 31488, 31507, 31526,
 31544, 31563, 31581, 31598, 31616, 31633, 31650, 31667,
 31683, 31700, 31716, 31731, 31747, 31762, 31777, 31792,
 31807, 31821, 31836, 31850, 31864, 31877, 31891, 31904,
 31917, 31930, 31942, 31955, 31967, 31979, 31991, 32003,
 32015, 32026, 32037, 32048, 32059, 32070, 32081, 32091,
 32101, 32111, 32121, 32131, 32141, 32150, 32160, 32169,
 32178, 32187, 32196, 32205, 32213, 32222, 32230, 32238,
 32246, 32254, 32262, 32270, 32277, 32285, 32292, 32300,
 32307, 32314, 32321, 32327, 32334, 32341, 32347, 32354,
 32360, 32366, 32373, 32379, 32385, 32390, 32396, 32402,
 32407, 32413, 32418, 32424, 32429, 32434, 32439, 32444,
 32449, 32454, 32459, 32464, 32468, 32473, 32478, 32482,
 32486, 32491, 32495, 32499, 32503, 32507, 32511, 32515,
 32519, 32523, 32527, 32530, 32534, 32538, 32541, 32545,
 32548, 32552, 32555, 32558, 32561, 32565, 32568, 32571,
 32574, 32577, 32580, 32583, 32585, 32588, 32591, 32594,
 32596, 32599, 32602, 32604, 32607, 32609, 32612, 32614,
 32616, 32619, 32621, 32623, 32626, 32628, 32630, 32632,
 32634, 32636, 32638, 32640, 32642, 32644, 32646, 32648,
 32650, 32652, 32653, 32655, 32657, 32659, 32660, 32662,
 32664, 32665, 32667, 32668, 32670, 32671, 32673, 32674,
 32676, 32677, 32679, 32680, 32681, 32683, 32684, 32685,
 32686, 32688, 32689, 32690, 32691, 32693, 32694, 32695,
 32696, 32697, 32698, 32699, 32700, 32701, 32702, 32703,
 32704, 32705, 32706, 32707, 32708, 32709, 32710, 32711,
 32712, 32713, 32713, 32714, 32715, 32716, 32717, 32718,
 32718, 32719, 32720, 32721, 32721, 32722, 32723, 32723,
 32724, 32725, 32725, 32726, 32727, 32727, 32728, 32729,
 32729, 32730, 32730, 32731, 32731, 32732, 32733, 32733,
 32734, 32734, 32735, 32735, 32736, 32736, 32737, 32737,
 32738, 32738, 32739, 32739, 32739, 32740, 32740, 32741,
 32741, 32742, 32742, 32742, 32743, 32743, 32744, 32744,
 32744, 32745, 32745, 32745, 32746, 32746, 32746, 32747,
 32747, 32747, 32748, 32748, 32748, 32749, 32749, 32749,
 32749, 32750, 32750, 32750, 32750, 32751, 32751, 32751,
 32752, 32752, 32752, 32752, 32752, 32753, 32753, 32753,
 32753, 32754, 32754, 32754, 32754, 32754, 32755, 32755,
 32755, 32755, 32755, 32756, 32756, 32756, 32756, 32756,
 32757, 32757, 32757, 32757, 32757, 32757, 32757, 32758,
 32758, 32758, 32758, 32758, 32758, 32759, 32759, 32759,
 32759, 32759, 32759, 32759, 32759, 32760, 32760, 32760,
 32760, 32760, 32760, 32760, 32760, 32761, 32761, 32761,
 32761, 32761, 32761, 32761, 32761, 32761, 32761, 32762,
 32762, 32762, 32762, 32762, 32762, 32762, 32762, 32762,
 32762, 32762, 32762, 32763, 32763, 32763, 32763, 32763,
 32763, 32763, 32763, 32763, 32763, 32763, 32763, 32763,
 32763, 32764, 32764, 32764, 32764, 32764, 32764, 32764,
 32764, 32764, 32764, 32764, 32764, 32764, 32764, 32764,
 32764, 32764, 32764, 32764, 32765, 32765, 32765, 32765,
 32765, 32765, 32765, 32765, 32765, 32765, 32765, 32765,
 32765, 32765, 32765, 32765, 32765, 32765, 32765, 32765,
 32765, 32765, 32765, 32765, 32765, 32765, 32766, 32766,
 32766, 32766, 32766, 32766, 32766, 32766, 32766, 32766,
 32766, 32766, 32766, 32766, 32766, 32766, 32766, 32766,
 32766, 32766, 32766, 32766, 32766, 32766, 32766, 32766,
 32766, 32766, 32766, 32766, 32766, 32766, 32766, 32766,
 32766, 32766, 32766, 32766, 32766, 32766, 32766, 32766,
 32766, 32766, 32767, 32767, 32767, 32767, 32767, 32767
};

// stdt[i]=count of -i or i in botton or top of stretcht[]
static const U8 stdt[712]={
    64,   128,   128,   128,   128,   128,   127,   128,
   127,   128,   127,   127,   127,   127,   126,   126,
   126,   126,   126,   125,   125,   124,   125,   124,
   123,   123,   123,   123,   122,   122,   121,   121,
   120,   120,   119,   119,   118,   118,   118,   116,
   117,   115,   116,   114,   114,   113,   113,   112,
   112,   111,   110,   110,   109,   108,   108,   107,
   106,   106,   105,   104,   104,   102,   103,   101,
   101,   100,    99,    98,    98,    97,    96,    96,
    94,    94,    94,    92,    92,    91,    90,    89,
    89,    88,    87,    86,    86,    84,    84,    84,
    82,    82,    81,    80,    79,    79,    78,    77,
    76,    76,    75,    74,    73,    73,    72,    71,
    70,    70,    69,    68,    67,    67,    66,    65,
    65,    64,    63,    62,    62,    61,    61,    59,
    59,    59,    57,    58,    56,    56,    55,    54,
    54,    53,    52,    52,    51,    51,    50,    49,
    49,    48,    48,    47,    47,    45,    46,    44,
    45,    43,    43,    43,    42,    41,    41,    40,
    40,    40,    39,    38,    38,    37,    37,    36,
    36,    36,    35,    34,    34,    34,    33,    32,
    33,    32,    31,    31,    30,    31,    29,    30,
    28,    29,    28,    28,    27,    27,    27,    26,
    26,    25,    26,    24,    25,    24,    24,    23,
    23,    23,    23,    22,    22,    21,    22,    21,
    20,    21,    20,    19,    20,    19,    19,    19,
    18,    18,    18,    18,    17,    17,    17,    17,
    16,    16,    16,    16,    15,    15,    15,    15,
    15,    14,    14,    14,    14,    13,    14,    13,
    13,    13,    12,    13,    12,    12,    12,    11,
    12,    11,    11,    11,    11,    11,    10,    11,
    10,    10,    10,    10,     9,    10,     9,     9,
     9,     9,     9,     8,     9,     8,     9,     8,
     8,     8,     7,     8,     8,     7,     7,     8,
     7,     7,     7,     6,     7,     7,     6,     6,
     7,     6,     6,     6,     6,     6,     6,     5,
     6,     5,     6,     5,     5,     5,     5,     5,
     5,     5,     5,     5,     4,     5,     4,     5,
     4,     4,     5,     4,     4,     4,     4,     4,
     4,     3,     4,     4,     3,     4,     4,     3,
     3,     4,     3,     3,     3,     4,     3,     3,
     3,     3,     3,     3,     2,     3,     3,     3,
     2,     3,     2,     3,     3,     2,     2,     3,
     2,     2,     3,     2,     2,     2,     2,     3,
     2,     2,     2,     2,     2,     2,     1,     2,
     2,     2,     2,     1,     2,     2,     2,     1,
     2,     1,     2,     2,     1,     2,     1,     2,
     1,     1,     2,     1,     1,     2,     1,     1,
     2,     1,     1,     1,     1,     2,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     0,     1,     1,     1,     1,     0,
     1,     1,     1,     0,     1,     1,     1,     0,
     1,     1,     0,     1,     1,     0,     1,     0,
     1,     1,     0,     1,     0,     1,     0,     1,
     0,     1,     0,     1,     0,     1,     0,     1,
     0,     1,     0,     1,     0,     1,     0,     0,
     1,     0,     1,     0,     0,     1,     0,     1,
     0,     0,     1,     0,     0,     1,     0,     0,
     1,     0,     0,     1,     0,     0,     0,     1,
     0,     0,     1,     0,     0,     0,     1,     0,
     0,     0,     1,     0,     0,     0,     1,     0,
     0,     0,     0,     1,     0,     0,     0,     0,
     1,     0,     0,     0,     0,     1,     0,     0,
     0,     0,     0,     1,     0,     0,     0,     0,
     0,     1,     0,     0,     0,     0,     0,     0,
     1,     0,     0,     0,     0,     0,     0,     0,
     1,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     1,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     1,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     1,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     1,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     1,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     1,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     1,     0
};

// Initailize model-independent tables
Predictor::Predictor(ZPAQL& zr):
    c8(1), hmap4(1), z(zr) {
 

  // Initialize tables
  memcpy(dt2k, sdt2k, sizeof(dt2k));
  memcpy(dt, sdt, sizeof(dt));
  memcpy(squasht, ssquasht, sizeof(squasht));

  // ssquasht[i]=int(32768.0/(1+exp((i-2048)*(-1.0/64))));
  // Copy middle 1344 of 4096 entries.
  memset(squasht, 0, 1376*2);
  memcpy(squasht+1376, ssquasht, 1344*2);
  for (int i=2720; i<4096; ++i) squasht[i]=32767;

  // sstretcht[i]=int(log((i+0.5)/(32767.5-i))*64+0.5+100000)-100000;
  int k=16384;
  for (int i=0; i<712; ++i)
    for (int j=stdt[i]; j>0; --j)
      stretcht[k++]=i;

  for (int i=0; i<16384; ++i)
    stretcht[i]=-stretcht[32767-i];

#ifndef NDEBUG
  // Verify floating point math for squash() and stretch()
  U32 sqsum=0, stsum=0;
  for (int i=32767; i>=0; --i)
    stsum=stsum*3+stretch(i);
  for (int i=4095; i>=0; --i)
    sqsum=sqsum*3+squash(i-2048);
 
#endif

  pcode=0;
  pcode_size=0;
}

Predictor::~Predictor() {
  allocx(pcode, pcode_size, 0);  // free executable memory
}

// Initialize the predictor with a new model in z
void Predictor::init() {

  // Clear old JIT code if any
  allocx(pcode, pcode_size, 0);

  // Initialize context hash function
  z.inith();

  // Initialize predictions
  for (int i=0; i<256; ++i) h[i]=p[i]=0;

  // Initialize components
  for (int i=0; i<256; ++i)  // clear old model
    comp[i].init();
  int n=z.header[6]; // hsize[0..1] hh hm ph pm n (comp)[n] END 0[128] (hcomp) END
  const U8* cp=&z.header[7];  // start of component list
  for (int i=0; i<n; ++i) {
  
    Component& cr=comp[i];
    switch(cp[0]) {
      case CONS:  // c
        p[i]=(cp[1]-128)*4;
        break;
      case CM: // sizebits limit
        if (cp[1]>32) error("max size for CM is 32");
        cr.cm.resize(1, cp[1]);  // packed CM (22 bits) + CMCOUNT (10 bits)
        cr.limit=cp[2]*4;
        for (size_t j=0; j<cr.cm.size(); ++j)
          cr.cm[j]=0x80000000;
        break;
      case ICM: // sizebits
        if (cp[1]>26) error("max size for ICM is 26");
        cr.limit=1023;
        cr.cm.resize(256);
        cr.ht.resize(64, cp[1]);
        for (size_t j=0; j<cr.cm.size(); ++j)
          cr.cm[j]=st.cminit(j);
        break;
      case MATCH:  // sizebits
        if (cp[1]>32 || cp[2]>32) error("max size for MATCH is 32 32");
        cr.cm.resize(1, cp[1]);  // index
        cr.ht.resize(1, cp[2]);  // buf
        cr.ht(0)=1;
        break;
      case AVG: // j k wt
        if (cp[1]>=i) error("AVG j >= i");
        if (cp[2]>=i) error("AVG k >= i");
        break;
      case MIX2:  // sizebits j k rate mask
        if (cp[1]>32) error("max size for MIX2 is 32");
        if (cp[3]>=i) error("MIX2 k >= i");
        if (cp[2]>=i) error("MIX2 j >= i");
        cr.c=(size_t(1)<<cp[1]); // size (number of contexts)
        cr.a16.resize(1, cp[1]);  // wt[size][m]
        for (size_t j=0; j<cr.a16.size(); ++j)
          cr.a16[j]=32768;
        break;
      case MIX: {  // sizebits j m rate mask
        if (cp[1]>32) error("max size for MIX is 32");
        if (cp[2]>=i) error("MIX j >= i");
        if (cp[3]<1 || cp[3]>i-cp[2]) error("MIX m not in 1..i-j");
        int m=cp[3];  // number of inputs
      
        cr.c=(size_t(1)<<cp[1]); // size (number of contexts)
        cr.cm.resize(m, cp[1]);  // wt[size][m]
        for (size_t j=0; j<cr.cm.size(); ++j)
          cr.cm[j]=65536/m;
        break;
      }
      case ISSE:  // sizebits j
        if (cp[1]>32) error("max size for ISSE is 32");
        if (cp[2]>=i) error("ISSE j >= i");
        cr.ht.resize(64, cp[1]);
        cr.cm.resize(512);
        for (int j=0; j<256; ++j) {
          cr.cm[j*2]=1<<15;
          cr.cm[j*2+1]=clamp512k(stretch(st.cminit(j)>>8)<<10);
        }
        break;
      case SSE: // sizebits j start limit
        if (cp[1]>32) error("max size for SSE is 32");
        if (cp[2]>=i) error("SSE j >= i");
        if (cp[3]>cp[4]*4) error("SSE start > limit*4");
        cr.cm.resize(32, cp[1]);
        cr.limit=cp[4]*4;
        for (size_t j=0; j<cr.cm.size(); ++j)
          cr.cm[j]=squash((j&31)*64-992)<<17|cp[3];
        break;
      default: error("unknown component type");
    }
 
    cp+=compsize[*cp];
   
  }
}

// Return next bit prediction using interpreted COMP code
int Predictor::predict0() {
  

  // Predict next bit
  int n=z.header[6];

  const U8* cp=&z.header[7];
 
  for (int i=0; i<n; ++i) {
   
    Component& cr=comp[i];
    switch(cp[0]) {
      case CONS:  // c
        break;
      case CM:  // sizebits limit
        cr.cxt=h[i]^hmap4;
        p[i]=stretch(cr.cm(cr.cxt)>>17);
        break;
      case ICM: // sizebits
      
        if (c8==1 || (c8&0xf0)==16) cr.c=find(cr.ht, cp[1]+2, h[i]+16*c8);
        cr.cxt=cr.ht[cr.c+(hmap4&15)];
        p[i]=stretch(cr.cm(cr.cxt)>>8);
        break;
      case MATCH: // sizebits bufbits: a=len, b=offset, c=bit, cxt=bitpos,
                  //                   ht=buf, limit=pos
    
        if (cr.a==0) p[i]=0;
        else {
          cr.c=(cr.ht(cr.limit-cr.b)>>(7-cr.cxt))&1; // predicted bit
          p[i]=stretch(dt2k[cr.a]*(cr.c*-2+1)&32767);
        }
        break;
      case AVG: // j k wt
        p[i]=(p[cp[1]]*cp[3]+p[cp[2]]*(256-cp[3]))>>8;
        break;
      case MIX2: { // sizebits j k rate mask
                   // c=size cm=wt[size] cxt=input
        cr.cxt=((h[i]+(c8&cp[5]))&(cr.c-1));
     
        int w=cr.a16[cr.cxt];
        p[i]=(w*p[cp[2]]+(65536-w)*p[cp[3]])>>16;
    
      }
        break;
      case MIX: {  // sizebits j m rate mask
                   // c=size cm=wt[size][m] cxt=index of wt in cm
        int m=cp[3];
      
        cr.cxt=h[i]+(c8&cp[5]);
        cr.cxt=(cr.cxt&(cr.c-1))*m; // pointer to row of weights
    
        int* wt=(int*)&cr.cm[cr.cxt];
        p[i]=0;
        for (int j=0; j<m; ++j)
          p[i]+=(wt[j]>>8)*p[cp[2]+j];
        p[i]=clamp2k(p[i]>>8);
      }
        break;
      case ISSE: { // sizebits j -- c=hi, cxt=bh
       
        if (c8==1 || (c8&0xf0)==16)
          cr.c=find(cr.ht, cp[1]+2, h[i]+16*c8);
        cr.cxt=cr.ht[cr.c+(hmap4&15)];  // bit history
        int *wt=(int*)&cr.cm[cr.cxt*2];
        p[i]=clamp2k((wt[0]*p[cp[2]]+wt[1]*64)>>16);
      }
        break;
      case SSE: { // sizebits j start limit
        cr.cxt=(h[i]+c8)*32;
        int pq=p[cp[2]]+992;
        if (pq<0) pq=0;
        if (pq>1983) pq=1983;
        int wt=pq&63;
        pq>>=6;
      
        cr.cxt+=pq;
        p[i]=stretch(((cr.cm(cr.cxt)>>10)*(64-wt)+(cr.cm(cr.cxt+1)>>10)*wt)>>13);
        cr.cxt+=wt>>5;
      }
        break;
      default:
        error("component predict not implemented");
    }
    cp+=compsize[cp[0]];
   
  }

  return squash(p[n-1]);
}

// Update model with decoded bit y (0...1)
void Predictor::update0(int y) {
  

  // Update components
  const U8* cp=&z.header[7];
  int n=z.header[6];

  for (int i=0; i<n; ++i) {
    Component& cr=comp[i];
    switch(cp[0]) {
      case CONS:  // c
        break;
      case CM:  // sizebits limit
        train(cr, y);
        break;
      case ICM: { // sizebits: cxt=ht[b]=bh, ht[c][0..15]=bh row, cxt=bh
        cr.ht[cr.c+(hmap4&15)]=st.next(cr.ht[cr.c+(hmap4&15)], y);
        U32& pn=cr.cm(cr.cxt);
        pn+=int(y*32767-(pn>>8))>>2;
      }
        break;
      case MATCH: // sizebits bufbits:
                  //   a=len, b=offset, c=bit, cm=index, cxt=bitpos
                  //   ht=buf, limit=pos
      {
      
        if (int(cr.c)!=y) cr.a=0;  // mismatch?
        cr.ht(cr.limit)+=cr.ht(cr.limit)+y;
        if (++cr.cxt==8) {
          cr.cxt=0;
          ++cr.limit;
          cr.limit&=(1<<cp[2])-1;
          if (cr.a==0) {  // look for a match
            cr.b=cr.limit-cr.cm(h[i]);
            if (cr.b&(cr.ht.size()-1))
              while (cr.a<255
                     && cr.ht(cr.limit-cr.a-1)==cr.ht(cr.limit-cr.a-cr.b-1))
                ++cr.a;
          }
          else cr.a+=cr.a<255;
          cr.cm(h[i])=cr.limit;
        }
      }
        break;
      case AVG:  // j k wt
        break;
      case MIX2: { // sizebits j k rate mask
                   // cm=wt[size], cxt=input
      
        int err=(y*32767-squash(p[i]))*cp[4]>>5;
        int w=cr.a16[cr.cxt];
        w+=(err*(p[cp[2]]-p[cp[3]])+(1<<12))>>13;
        if (w<0) w=0;
        if (w>65535) w=65535;
        cr.a16[cr.cxt]=w;
      }
        break;
      case MIX: {   // sizebits j m rate mask
                    // cm=wt[size][m], cxt=input
        int m=cp[3];
      
        int err=(y*32767-squash(p[i]))*cp[4]>>4;
        int* wt=(int*)&cr.cm[cr.cxt];
        for (int j=0; j<m; ++j)
          wt[j]=clamp512k(wt[j]+((err*p[cp[2]+j]+(1<<12))>>13));
      }
        break;
      case ISSE: { // sizebits j  -- c=hi, cxt=bh
    
        int err=y*32767-squash(p[i]);
        int *wt=(int*)&cr.cm[cr.cxt*2];
        wt[0]=clamp512k(wt[0]+((err*p[cp[2]]+(1<<12))>>13));
        wt[1]=clamp512k(wt[1]+((err+16)>>5));
        cr.ht[cr.c+(hmap4&15)]=st.next(cr.cxt, y);
      }
        break;
      case SSE:  // sizebits j start limit
        train(cr, y);
        break;
      default:
		exit(0);
       /// assert(0);
    }
    cp+=compsize[cp[0]];
 
  }
  

  // Save bit y in c8, hmap4
  c8+=c8+y;
  if (c8>=256) {
    z.run(c8-256);
    hmap4=1;
    c8=1;
    for (int i=0; i<n; ++i) h[i]=z.H(i);
  }
  else if (c8>=16 && c8<32)
    hmap4=(hmap4&0xf)<<5|y<<4|1;
  else
    hmap4=(hmap4&0x1f0)|(((hmap4&0xf)*2+y)&0xf);
}

// Find cxt row in hash table ht. ht has rows of 16 indexed by the
// low sizebits of cxt with element 0 having the next higher 8 bits for
// collision detection. If not found after 3 adjacent tries, replace the
// row with lowest element 1 as priority. Return index of row.
size_t Predictor::find(Array<U8>& ht, int sizebits, U32 cxt) {
 
  int chk=cxt>>sizebits&255;
  size_t h0=(cxt*16)&(ht.size()-16);
  if (ht[h0]==chk) return h0;
  size_t h1=h0^16;
  if (ht[h1]==chk) return h1;
  size_t h2=h0^32;
  if (ht[h2]==chk) return h2;
  if (ht[h0+1]<=ht[h1+1] && ht[h0+1]<=ht[h2+1])
    return memset(&ht[h0], 0, 16), ht[h0]=chk, h0;
  else if (ht[h1+1]<ht[h2+1])
    return memset(&ht[h1], 0, 16), ht[h1]=chk, h1;
  else
    return memset(&ht[h2], 0, 16), ht[h2]=chk, h2;
}

/////////////////////// Decoder ///////////////////////

Decoder::Decoder(ZPAQL& z):
    in(0), low(1), high(0xFFFFFFFF), curr(0), pr(z), buf(BUFSIZE) {
}

void Decoder::init() {
  pr.init();
  if (pr.isModeled()) low=1, high=0xFFFFFFFF, curr=0;
  else low=high=curr=0;
}

// Read un-modeled input into buf[low=0..high-1]
// with curr remaining in subblock to read.
void Decoder::loadbuf() {
 
  if (curr==0) {
    for (int i=0; i<4; ++i) {
      int c=in->get();
      if (c<0) error("unexpected end of input");
      curr=curr<<8|c;
    }
  }
  U32 n=buf.size();
  if (n>curr) n=curr;
  high=in->read(&buf[0], n);
  curr-=high;
  low=0;
}

// Return next bit of decoded input, which has 16 bit probability p of being 1
int Decoder::decode(int p) {

  if (curr<low || curr>high) error("archive corrupted");

  U32 mid=low+U32(((high-low)*U64(U32(p)))>>16);  // split range
 
  int y;
  if (curr<=mid) y=1, high=mid;  // pick half
  else y=0, low=mid+1;
  while ((high^low)<0x1000000) { // shift out identical leading bytes
    high=high<<8|255;
    low=low<<8;
    low+=(low==0);
    int c=in->get();
    if (c<0) error("unexpected end of file");
    curr=curr<<8|c;
  }
  return y;
}

// Decompress 1 byte or -1 at end of input
int Decoder::decompress() {
  if (pr.isModeled()) {  // n>0 components?
    if (curr==0) {  // segment initialization
      for (int i=0; i<4; ++i)
        curr=curr<<8|in->get();
    }
    if (decode(0)) {
      if (curr!=0) error("decoding end of stream");
      return -1;
    }
    else {
      int c=1;
      while (c<256) {  // get 8 bits
        int p=pr.predict()*2+1;
        c+=c+decode(p);
        pr.update(c&1);
      }
      return c-256;
    }
  }
  else {
    if (low==high) loadbuf();
    if (low==high) return -1;
    return buf[low++]&255;
  }
}

// Find end of compressed data and return next byte
int Decoder::skip() {
  int c=-1;
  if (pr.isModeled()) {
    while (curr==0)  // at start?
      curr=in->get();
    while (curr && (c=in->get())>=0)  // find 4 zeros
      curr=curr<<8|c;
    while ((c=in->get())==0) ;  // might be more than 4
    return c;
  }
  else {
    if (curr==0)  // at start?
      for (int i=0; i<4 && (c=in->get())>=0; ++i) curr=curr<<8|c;
    while (curr>0) {
      U32 n=BUFSIZE;
      if (n>curr) n=curr;
      U32 n1=in->read(&buf[0], n);
      curr-=n1;
      if (n1<1) return -1;
      if (curr==0)
        for (int i=0; i<4 && (c=in->get())>=0; ++i) curr=curr<<8|c;
    }
    if (c>=0) c=in->get();
    return c;
  }
}

////////////////////// PostProcessor //////////////////////

// Copy ph, pm from block header
void PostProcessor::init(int h, int m) {
  state=hsize=0;
  ph=h;
  pm=m;
  z.clear();
}

// (PASS=0 | PROG=1 psize[0..1] pcomp[0..psize-1]) data... EOB=-1
// Return state: 1=PASS, 2..4=loading PROG, 5=PROG loaded
int PostProcessor::write(int c) {

  switch (state) {
    case 0:  // initial state
      if (c<0) error("Unexpected EOS");
      state=c+1;  // 1=PASS, 2=PROG
      if (state>2) error("unknown post processing type");
      if (state==1) z.clear();
      break;
    case 1:  // PASS
      z.outc(c);
      break;
    case 2: // PROG
      if (c<0) error("Unexpected EOS");
      hsize=c;  // low byte of size
      state=3;
      break;
    case 3:  // PROG psize[0]
      if (c<0) error("Unexpected EOS");
      hsize+=c*256;  // high byte of psize
      z.header.resize(hsize+300);
      z.cend=8;
      z.hbegin=z.hend=z.cend+128;
      z.header[4]=ph;
      z.header[5]=pm;
      state=4;
      break;
    case 4:  // PROG psize[0..1] pcomp[0...]
      if (c<0) error("Unexpected EOS");
     
      z.header[z.hend++]=c;  // one byte of pcomp
      if (z.hend-z.hbegin==hsize) {  // last byte of pcomp?
        hsize=z.cend-2+z.hend-z.hbegin;
        z.header[0]=hsize&255;  // header size with empty COMP
        z.header[1]=hsize>>8;
        z.initp();
        state=5;
      }
      break;
    case 5:  // PROG ... data
      z.run(c);
      if (c<0) z.flush();
      break;
  }
  return state;
}

/////////////////////// Decompresser /////////////////////

// Find the start of a block and return true if found. Set memptr
// to memory used.
bool Decompresser::findBlock(double* memptr) {


  // Find start of block
  U32 h1=0x3D49B113, h2=0x29EB7F93, h3=0x2614BE13, h4=0x3828EB13;
  // Rolling hashes initialized to hash of first 13 bytes
  int c;
  while ((c=dec.in->get())!=-1) {
    h1=h1*12+c;
    h2=h2*20+c;
    h3=h3*28+c;
    h4=h4*44+c;
    if (h1==0xB16B88F1 && h2==0xFF5376F1 && h3==0x72AC5BF1 && h4==0x2F909AF1)
      break;  // hash of 16 byte string
  }
  if (c==-1) return false;

  // Read header
  if ((c=dec.in->get())!=1 && c!=2) error("unsupported ZPAQ level");
  if (dec.in->get()!=1) error("unsupported ZPAQL type");
  z.read(dec.in);
  if (c==1 && z.header.isize()>6 && z.header[6]==0)
    error("ZPAQ level 1 requires at least 1 component");
  if (memptr) *memptr=z.memory();
  state=FILENAME;
  decode_state=FIRSTSEG;
  return true;
}

// Read the start of a segment (1) or end of block code (255).
// If a segment is found, write the filename and return true, else false.
bool Decompresser::findFilename(Writer* filename) {

  int c=dec.in->get();
  if (c==1) {  // segment found
    while (true) {
      c=dec.in->get();
      if (c==-1) error("unexpected EOF");
      if (c==0) {
        state=COMMENT;
        return true;
      }
      if (filename) filename->put(c);
    }
  }
  else if (c==255) {  // end of block found
    state=BLOCK;
    return false;
  }
  else
    error("missing segment or end of block");
  return false;
}

// Read the comment from the segment header
void Decompresser::readComment(Writer* comment) {
 
  state=DATA;
  while (true) {
    int c=dec.in->get();
    if (c==-1) error("unexpected EOF");
    if (c==0) break;
    if (comment) comment->put(c);
  }
  if (dec.in->get()!=0) error("missing reserved byte");
}

// Decompress n bytes, or all if n < 0. Return false if done
bool Decompresser::decompress(int n) {
  

  // Initialize models to start decompressing block
  if (decode_state==FIRSTSEG) {
    dec.init();
   
    pp.init(z.header[4], z.header[5]);
    decode_state=SEG;
  }

  // Decompress and load PCOMP into postprocessor
  while ((pp.getState()&3)!=1)
    pp.write(dec.decompress());

  // Decompress n bytes, or all if n < 0
  while (n) {
    int c=dec.decompress();
    pp.write(c);
    if (c==-1) {
      state=SEGEND;
      return false;
    }
    if (n>0) --n;
  }
  return true;
}

// Read end of block. If a SHA1 checksum is present, write 1 and the
// 20 byte checksum into sha1string, else write 0 in first byte.
// If sha1string is 0 then discard it.
void Decompresser::readSegmentEnd(char* sha1string) {
  

  // Skip remaining data if any and get next byte
  int c=0;
  if (state==DATA) {
    c=dec.skip();
    decode_state=SKIP;
  }
  else if (state==SEGEND)
    c=dec.in->get();
  state=FILENAME;

  // Read checksum
  if (c==254) {
    if (sha1string) sha1string[0]=0;  // no checksum
  }
  else if (c==253) {
    if (sha1string) sha1string[0]=1;
    for (int i=1; i<=20; ++i) {
      c=dec.in->get();
      if (sha1string) sha1string[i]=c;
    }
  }
  else
    error("missing end of segment marker");
}

/////////////////////////// decompress() //////////////////////

void decompress(Reader* in, Writer* out) {
  Decompresser d;
  d.setInput(in);
  d.setOutput(out);
  while (d.findBlock()) {       // don't calculate memory
    while (d.findFilename()) {  // discard filename
      d.readComment();          // discard comment
      d.decompress();           // to end of segment
      d.readSegmentEnd();       // discard sha1string
    }
  }
}

/////////////////////////// Encoder ///////////////////////////

// Initialize for start of block
void Encoder::init() {
  low=1;
  high=0xFFFFFFFF;
  pr.init();
  if (!pr.isModeled()) low=0, buf.resize(1<<16);
}

// compress bit y having probability p/64K
void Encoder::encode(int y, int p) {
 
  U32 mid=low+U32(((high-low)*U64(U32(p)))>>16);  // split range

  if (y) high=mid; else low=mid+1; // pick half
  while ((high^low)<0x1000000) { // write identical leading bytes
    out->put(high>>24);  // same as low>>24
    high=high<<8|255;
    low=low<<8;
    low+=(low==0); // so we don't code 4 0 bytes in a row
  }
}

// compress byte c (0..255 or -1=EOS)
void Encoder::compress(int c) {

  if (pr.isModeled()) {
    if (c==-1)
      encode(1, 0);
    else {
  
      encode(0, 0);
      for (int i=7; i>=0; --i) {
        int p=pr.predict()*2+1;

        int y=c>>i&1;
        encode(y, p);
        pr.update(y);
      }
    }
  }
  else {
    if (low && (c<0 || low==buf.size())) {
      out->put((low>>24)&255);
      out->put((low>>16)&255);
      out->put((low>>8)&255);
      out->put(low&255);
      out->write(&buf[0], low);
      low=0;
    }
    if (c>=0) buf[low++]=c;
  }
}

//////////////////////////// Compiler /////////////////////////

// Component names
const char* compname[256]=
  {"","const","cm","icm","match","avg","mix2","mix","isse","sse",0};

// Opcodes
const char* opcodelist[272]={
"error","a++",  "a--",  "a!",   "a=0",  "",     "",     "a=r",
"b<>a", "b++",  "b--",  "b!",   "b=0",  "",     "",     "b=r",
"c<>a", "c++",  "c--",  "c!",   "c=0",  "",     "",     "c=r",
"d<>a", "d++",  "d--",  "d!",   "d=0",  "",     "",     "d=r",
"*b<>a","*b++", "*b--", "*b!",  "*b=0", "",     "",     "jt",
"*c<>a","*c++", "*c--", "*c!",  "*c=0", "",     "",     "jf",
"*d<>a","*d++", "*d--", "*d!",  "*d=0", "",     "",     "r=a",
"halt", "out",  "",     "hash", "hashd","",     "",     "jmp",
"a=a",  "a=b",  "a=c",  "a=d",  "a=*b", "a=*c", "a=*d", "a=",
"b=a",  "b=b",  "b=c",  "b=d",  "b=*b", "b=*c", "b=*d", "b=",
"c=a",  "c=b",  "c=c",  "c=d",  "c=*b", "c=*c", "c=*d", "c=",
"d=a",  "d=b",  "d=c",  "d=d",  "d=*b", "d=*c", "d=*d", "d=",
"*b=a", "*b=b", "*b=c", "*b=d", "*b=*b","*b=*c","*b=*d","*b=",
"*c=a", "*c=b", "*c=c", "*c=d", "*c=*b","*c=*c","*c=*d","*c=",
"*d=a", "*d=b", "*d=c", "*d=d", "*d=*b","*d=*c","*d=*d","*d=",
"",     "",     "",     "",     "",     "",     "",     "",
"a+=a", "a+=b", "a+=c", "a+=d", "a+=*b","a+=*c","a+=*d","a+=",
"a-=a", "a-=b", "a-=c", "a-=d", "a-=*b","a-=*c","a-=*d","a-=",
"a*=a", "a*=b", "a*=c", "a*=d", "a*=*b","a*=*c","a*=*d","a*=",
"a/=a", "a/=b", "a/=c", "a/=d", "a/=*b","a/=*c","a/=*d","a/=",
"a%=a", "a%=b", "a%=c", "a%=d", "a%=*b","a%=*c","a%=*d","a%=",
"a&=a", "a&=b", "a&=c", "a&=d", "a&=*b","a&=*c","a&=*d","a&=",
"a&~a", "a&~b", "a&~c", "a&~d", "a&~*b","a&~*c","a&~*d","a&~",
"a|=a", "a|=b", "a|=c", "a|=d", "a|=*b","a|=*c","a|=*d","a|=",
"a^=a", "a^=b", "a^=c", "a^=d", "a^=*b","a^=*c","a^=*d","a^=",
"a<<=a","a<<=b","a<<=c","a<<=d","a<<=*b","a<<=*c","a<<=*d","a<<=",
"a>>=a","a>>=b","a>>=c","a>>=d","a>>=*b","a>>=*c","a>>=*d","a>>=",
"a==a", "a==b", "a==c", "a==d", "a==*b","a==*c","a==*d","a==",
"a<a",  "a<b",  "a<c",  "a<d",  "a<*b", "a<*c", "a<*d", "a<",
"a>a",  "a>b",  "a>c",  "a>d",  "a>*b", "a>*c", "a>*d", "a>",
"",     "",     "",     "",     "",     "",     "",     "",
"",     "",     "",     "",     "",     "",     "",     "lj",
"post", "pcomp","end",  "if",   "ifnot","else", "endif","do",
"while","until","forever","ifl","ifnotl","elsel",";",    0};

// Advance in to start of next token. Tokens are delimited by white
// space. Comments inclosed in ((nested) parenthsis) are skipped.
void Compiler::next() {
  
  for (; *in; ++in) {
    if (*in=='\n') ++line;
    if (*in=='(') state+=1+(state<0);
    else if (state>0 && *in==')') --state;
    else if (state<0 && *in<=' ') state=0;
    else if (state==0 && *in>' ') {state=-1; break;}
  }
  if (!*in) error("unexpected end of config");
}

// convert to lower case
int tolower(int c) {return (c>='A' && c<='Z') ? c+'a'-'A' : c;}

// return true if in==word up to white space or '(', case insensitive
bool Compiler::matchToken(const char* word) {
  const char* a=in;
  for (; (*a>' ' && *a!='(' && *word); ++a, ++word)
    if (tolower(*a)!=tolower(*word)) return false;
  return !*word && (*a<=' ' || *a=='(');
}

// Print error message and exit
void Compiler::syntaxError(const char* msg, const char* expected) {
  Array<char> sbuf(128);  // error message to report
  char* s=&sbuf[0];
  strcat(s, "Config line ");
  for (int i=strlen(s), r=1000000; r; r/=10)  // append line number
    if (line/r) s[i++]='0'+line/r%10;
  strcat(s, " at ");
  for (int i=strlen(s); i<40 && *in>' '; ++i)  // append token found
    s[i]=*in++;
  strcat(s, ": ");
  strncat(s, msg, 40);  // append message
  if (expected) {
    strcat(s, ", expected: ");
    strncat(s, expected, 20);  // append expected token if any
  }
  error(s);
}

// Read a token, which must be in the NULL terminated list or else
// exit with an error. If found, return its index.
int Compiler::rtoken(const char* list[]) {

  next();
  for (int i=0; list[i]; ++i)
    if (matchToken(list[i]))
      return i;
  syntaxError("unexpected");

  return -1; // not reached
}

// Read a token which must be the specified value s
void Compiler::rtoken(const char* s) {

  next();
  if (!matchToken(s)) syntaxError("expected", s);
}

// Read a number in (low...high) or exit with an error
// For numbers like $N+M, return arg[N-1]+M
int Compiler::rtoken(int low, int high) {
  next();
  int r=0;
  if (in[0]=='$' && in[1]>='1' && in[1]<='9') {
    if (in[2]=='+') r=atoi(in+3);
    if (args) r+=args[in[1]-'1'];
  }
  else if (in[0]=='-' || (in[0]>='0' && in[0]<='9')) r=atoi(in);
  else syntaxError("expected a number");
  if (r<low) syntaxError("number too low");
  if (r>high) syntaxError("number too high");
  return r;
}

// Compile HCOMP or PCOMP code. Exit on error. Return
// code for end token (POST, PCOMP, END)
int Compiler::compile_comp(ZPAQL& z) {
  int op=0;
  const int comp_begin=z.hend;
  while (true) {
    op=rtoken(opcodelist);
    if (op==POST || op==PCOMP || op==END) break;
    int operand=-1; // 0...255 if 2 bytes
    int operand2=-1;  // 0...255 if 3 bytes
    if (op==IF) {
      op=JF;
      operand=0; // set later
      if_stack.push(z.hend+1); // save jump target location
    }
    else if (op==IFNOT) {
      op=JT;
      operand=0;
      if_stack.push(z.hend+1); // save jump target location
    }
    else if (op==IFL || op==IFNOTL) {  // long if
      if (op==IFL) z.header[z.hend++]=(JT);
      if (op==IFNOTL) z.header[z.hend++]=(JF);
      z.header[z.hend++]=(3);
      op=LJ;
      operand=operand2=0;
      if_stack.push(z.hend+1);
    }
    else if (op==ELSE || op==ELSEL) {
      if (op==ELSE) op=JMP, operand=0;
      if (op==ELSEL) op=LJ, operand=operand2=0;
      int a=if_stack.pop();  // conditional jump target location
   
      if (z.header[a-1]!=LJ) {  // IF, IFNOT
      
        int j=z.hend-a+1+(op==LJ); // offset at IF

        if (j>127) syntaxError("IF too big, try IFL, IFNOTL");
        z.header[a]=j;
      }
      else {  // IFL, IFNOTL
        int j=z.hend-comp_begin+2+(op==LJ);
     
        z.header[a]=j&255;
        z.header[a+1]=(j>>8)&255;
      }
      if_stack.push(z.hend+1);  // save JMP target location
    }
    else if (op==ENDIF) {
      int a=if_stack.pop();  // jump target address
  
      int j=z.hend-a-1;  // jump offset
   
      if (z.header[a-1]!=LJ) {
   
        if (j>127) syntaxError("IF too big, try IFL, IFNOTL, ELSEL\n");
        z.header[a]=j;
      }
      else {

        j=z.hend-comp_begin;
        z.header[a]=j&255;
        z.header[a+1]=(j>>8)&255;
      }
    }
    else if (op==DO) {
      do_stack.push(z.hend);
    }
    else if (op==WHILE || op==UNTIL || op==FOREVER) {
      int a=do_stack.pop();
  
      int j=a-z.hend-2;
 
      if (j>=-127) {  // backward short jump
        if (op==WHILE) op=JT;
        if (op==UNTIL) op=JF;
        if (op==FOREVER) op=JMP;
        operand=j&255;
      }
      else {  // backward long jump
        j=a-comp_begin;
    
        if (op==WHILE) {
          z.header[z.hend++]=(JF);
          z.header[z.hend++]=(3);
        }
        if (op==UNTIL) {
          z.header[z.hend++]=(JT);
          z.header[z.hend++]=(3);
        }
        op=LJ;
        operand=j&255;
        operand2=j>>8;
      }
    }
    else if ((op&7)==7) { // 2 byte operand, read N
      if (op==LJ) {
        operand=rtoken(0, 65535);
        operand2=operand>>8;
        operand&=255;
      }
      else if (op==JT || op==JF || op==JMP) {
        operand=rtoken(-128, 127);
        operand&=255;
      }
      else
        operand=rtoken(0, 255);
    }
    if (op>=0 && op<=255)
      z.header[z.hend++]=(op);
    if (operand>=0)
      z.header[z.hend++]=(operand);
    if (operand2>=0)
      z.header[z.hend++]=(operand2);
    if (z.hend>=z.header.isize()-130 || z.hend-z.hbegin+z.cend-2>65535)
      syntaxError("program too big");
  }
  z.header[z.hend++]=(0); // END
  return op;
}

// Compile a configuration file. Store COMP/HCOMP section in hcomp.
// If there is a PCOMP section, store it in pcomp and store the PCOMP
// command in pcomp_cmd. Replace "$1..$9+n" with args[0..8]+n

Compiler::Compiler(const char* in_, int* args_, ZPAQL& hz_, ZPAQL& pz_,
                   Writer* out2_): in(in_), args(args_), hz(hz_), pz(pz_),
                   out2(out2_), if_stack(1000), do_stack(1000) {
  line=1;
  state=0;
  hz.clear();
  pz.clear();
  hz.header.resize(68000); 

  // Compile the COMP section of header
  rtoken("comp");
  hz.header[2]=rtoken(0, 255);  // hh
  hz.header[3]=rtoken(0, 255);  // hm
  hz.header[4]=rtoken(0, 255);  // ph
  hz.header[5]=rtoken(0, 255);  // pm
  const int n=hz.header[6]=rtoken(0, 255);  // n
  hz.cend=7;
  for (int i=0; i<n; ++i) {
    rtoken(i, i);
    CompType type=CompType(rtoken(compname));
    hz.header[hz.cend++]=type;
    int clen=libzpaq::compsize[type&255];
    if (clen<1 || clen>10) syntaxError("invalid component");
    for (int j=1; j<clen; ++j)
      hz.header[hz.cend++]=rtoken(0, 255);  // component arguments
  }
  hz.header[hz.cend++];  // end
  hz.hbegin=hz.hend=hz.cend+128;

  // Compile HCOMP
  rtoken("hcomp");
  int op=compile_comp(hz);

  // Compute header size
  int hsize=hz.cend-2+hz.hend-hz.hbegin;
  hz.header[0]=hsize&255;
  hz.header[1]=hsize>>8;

  // Compile POST 0 END
  if (op==POST) {
    rtoken(0, 0);
    rtoken("end");
  }

  // Compile PCOMP pcomp_cmd ; program... END
  else if (op==PCOMP) {
    pz.header.resize(68000);
    pz.header[4]=hz.header[4];  // ph
    pz.header[5]=hz.header[5];  // pm
    pz.cend=8;
    pz.hbegin=pz.hend=pz.cend+128;

    // get pcomp_cmd ending with ";" (case sensitive)
    next();
    while (*in && *in!=';') {
      if (out2)
        out2->put(*in);
      ++in;
    }
    if (*in) ++in;

    // Compile PCOMP
    op=compile_comp(pz);
    int len=pz.cend-2+pz.hend-pz.hbegin;  // insert header size
 
    pz.header[0]=len&255;
    pz.header[1]=len>>8;
    if (op!=END)
      syntaxError("expected END");
  }
  else if (op!=END)
    syntaxError("expected END or POST 0 END or PCOMP cmd ; ... END");
}

///////////////////// Compressor //////////////////////

// Write 13 byte start tag
// "\x37\x6B\x53\x74\xA0\x31\x83\xD3\x8C\xB2\x28\xB0\xD3"

//////////////////////// ZPAQL::assemble() ////////////////////

#ifndef NOJIT

// Called by out
static void flush1(ZPAQL* z) {
  z->flush();
}

// return true if op is an undefined ZPAQL instruction
static bool iserr(int op) {
  return op==0 || (op>=120 && op<=127) || (op>=240 && op<=254)
    || op==58 || (op<64 && (op%8==5 || op%8==6));
}

// Write k bytes of x to rcode[o++] MSB first
static void put(U8* rcode, int n, int& o, U32 x, int k) {
  while (k-->0) {
    if (o<n) rcode[o]=(x>>(k*8))&255;
    ++o;
  }
}

// Write 4 bytes of x to rcode[o++] LSB first
static void put4lsb(U8* rcode, int n, int& o, U32 x) {
  for (int k=0; k<4; ++k) {
    if (o<n) rcode[o]=(x>>(k*8))&255;
    ++o;
  }
}

// Write a 1-4 byte x86 opcode without or with an 4 byte operand
// to rcode[o...]
#define put1(x) put(rcode, rcode_size, o, (x), 1)
#define put2(x) put(rcode, rcode_size, o, (x), 2)
#define put3(x) put(rcode, rcode_size, o, (x), 3)
#define put4(x) put(rcode, rcode_size, o, (x), 4)
#define put5(x,y) put4(x), put1(y)
#define put6(x,y) put4(x), put2(y)
#define put4r(x) put4lsb(rcode, rcode_size, o, x)
#define puta(x) t=U32(size_t(x)), put4r(t)
#define put1a(x,y) put1(x), puta(y)
#define put2a(x,y) put2(x), puta(y)
#define put3a(x,y) put3(x), puta(y)
#define put4a(x,y) put4(x), puta(y)
#define put5a(x,y,z) put4(x), put1(y), puta(z)
#define put2l(x,y) put2(x), t=U32(size_t(y)), put4r(t), \
  t=U32(size_t(y)>>(S*4)), put4r(t)

// Assemble ZPAQL in in the HCOMP section of header to rcode,
// but do not write beyond rcode_size. Return the number of
// bytes output or that would have been output.
// Execution starts at rcode[0] and returns 1 if successful or 0
// in case of a ZPAQL execution error.
int ZPAQL::assemble() {

  // x86? (not foolproof)
  const int S=sizeof(char*);      // 4 = x86, 8 = x86-64
  U32 t=0x12345678;
  if (*(char*)&t!=0x78 || (S!=4 && S!=8))
    error("JIT supported only for x86-32 and x86-64");

  const U8* hcomp=&header[hbegin];
  const int hlen=hend-hbegin+1;
  const int msize=m.size();
  const int hsize=h.size();
  static const int regcode[8]={2,6,7,5}; // a,b,c,d.. -> edx,esi,edi,ebp,eax..
  Array<int> it(hlen);            // hcomp -> rcode locations
  int done=0;  // number of instructions assembled (0..hlen)
  int o=5;  // rcode output index, reserve space for jmp

  // Code for the halt instruction (restore registers and return)
  const int halt=o;
  if (S==8) {
    put2l(0x48b9, &a);        // mov rcx, a
    put2(0x8911);             // mov [rcx], edx
    put2l(0x48b9, &b);        // mov rcx, b
    put2(0x8931);             // mov [rcx], esi
    put2l(0x48b9, &c);        // mov rcx, c
    put2(0x8939);             // mov [rcx], edi
    put2l(0x48b9, &d);        // mov rcx, d
    put2(0x8929);             // mov [rcx], ebp
    put2l(0x48b9, &f);        // mov rcx, f
    put2(0x8919);             // mov [rcx], ebx
    put4(0x4883c438);         // add rsp, 56
    put2(0x415f);             // pop r15
    put2(0x415e);             // pop r14
    put2(0x415d);             // pop r13
    put2(0x415c);             // pop r12
  }
  else {
    put2a(0x8915, &a);        // mov [a], edx
    put2a(0x8935, &b);        // mov [b], esi
    put2a(0x893d, &c);        // mov [c], edi
    put2a(0x892d, &d);        // mov [d], ebp
    put2a(0x891d, &f);        // mov [f], ebx
    put3(0x83c43c);           // add esp, 60
  }
  put1(0x5d);                 // pop ebp
  put1(0x5b);                 // pop ebx
  put1(0x5f);                 // pop edi
  put1(0x5e);                 // pop esi
  put1(0xc3);                 // ret

  // Code for the out instruction.
  // Store a=edx at outbuf[bufptr++]. If full, call flush1().
  const int outlabel=o;
  if (S==8) {
    put2l(0x48b8, &outbuf[0]);// mov rax, outbuf.p
    put2l(0x49ba, &bufptr);   // mov r10, &bufptr
    put3(0x418b0a);           // mov rcx, [r10]
    put3(0x881408);           // mov [rax+rcx], dl
    put2(0xffc1);             // inc rcx
    put3(0x41890a);           // mov [r10], ecx
    put2a(0x81f9, outbuf.size());  // cmp rcx, outbuf.size()
    put2(0x7401);             // jz L1
    put1(0xc3);               // ret
    put4(0x4883ec48);         // L1: sub rsp, 72  ; call flush1(this)
    put5(0x48897c24,64);      // mov [rsp+64], rdi
    put5(0x48897424,56);      // mov [rsp+56], rsi
    put5(0x48895424,48);      // mov [rsp+48], rdx
    put5(0x48894c24,40);      // mov [rsp+40], rcx
#if defined(unix) && !defined(__CYGWIN__)
    put2l(0x48bf, this);      // mov rdi, this
#else  // Windows
    put2l(0x48b9, this);      // mov rcx, this
#endif
    put2l(0x49bb, &flush1);   // mov r11, &flush1
    put3(0x41ffd3);           // call r11
    put5(0x488b4c24,40);      // mov rcx, [rsp+40]
    put5(0x488b5424,48);      // mov rdx, [rsp+48]
    put5(0x488b7424,56);      // mov rsi, [rsp+56]
    put5(0x488b7c24,64);      // mov rdi, [rsp+64]
    put4(0x4883c448);         // add rsp, 72
    put1(0xc3);               // ret
  }
  else {
    put1a(0xb8, &outbuf[0]);  // mov eax, outbuf.p
    put2a(0x8b0d, &bufptr);   // mov ecx, [bufptr]
    put3(0x881408);           // mov [eax+ecx], dl
    put2(0xffc1);             // inc ecx
    put2a(0x890d, &bufptr);   // mov [bufptr], ecx
    put2a(0x81f9, outbuf.size());  // cmp ecx, outbuf.size()
    put2(0x7401);             // jz L1
    put1(0xc3);               // ret
    put3(0x83ec0c);           // L1: sub esp, 12
    put4(0x89542404);         // mov [esp+4], edx
    put3a(0xc70424, this);    // mov [esp], this
    put1a(0xb8, &flush1);     // mov eax, &flush1
    put2(0xffd0);             // call eax
    put4(0x8b542404);         // mov edx, [esp+4]
    put3(0x83c40c);           // add esp, 12
    put1(0xc3);               // ret
  }

  // Set it[i]=1 for each ZPAQL instruction reachable from the previous
  // instruction + 2 if reachable by a jump (or 3 if both).
  it[0]=2;
 
  do {
    done=0;
    const int NONE=0x80000000;
    for (int i=0; i<hlen; ++i) {
      int op=hcomp[i];
      if (it[i]) {
        int next1=i+1+(op%8==7), next2=NONE; // next and jump targets
        if (iserr(op)) next1=NONE;  // error
        if (op==56) next1=NONE, next2=0;  // halt
        if (op==255) next1=NONE, next2=hcomp[i+1]+256*hcomp[i+2]; // lj
        if (op==39||op==47||op==63)next2=i+2+(hcomp[i+1]<<24>>24);// jt,jf,jmp
        if (op==63) next1=NONE;  // jmp
        if ((next2<0 || next2>=hlen) && next2!=NONE) next2=hlen-1; // error
        if (next1!=NONE && !(it[next1]&1)) it[next1]|=1, ++done;
        if (next2!=NONE && !(it[next2]&2)) it[next2]|=2, ++done;
      }
    }
  } while (done>0);

  // Set it[i] bits 2-3 to 4, 8, or 12 if a comparison
  //  (==, <, > respectively) does not need to save the result in f,
  // or if a conditional jump (jt, jf) does not need to read f.
  // This is true if a comparison is followed directly by a jt/jf,
  // the jt/jf is not a jump target, the byte before is not a jump
  // target (for a 2 byte comparison), and for the comparison instruction
  // if both paths after the jt/jf lead to another comparison or error
  // before another jt/jf. At most hlen steps are traced because after
  // that it must be an infinite loop.
  for (int i=0; i<hlen; ++i) {
    const int op1=hcomp[i]; // 216..239 = comparison
    const int i2=i+1+(op1%8==7);  // address of next instruction
    const int op2=hcomp[i2];  // 39,47 = jt,jf
    if (it[i] && op1>=216 && op1<240 && (op2==39 || op2==47)
        && it[i2]==1 && (i2==i+1 || it[i+1]==0)) {
      int code=(op1-208)/8*4; // 4,8,12 is ==,<,>
      it[i2]+=code;  // OK to test CF, ZF instead of f
      for (int j=0; j<2 && code; ++j) {  // trace each path from i2
        int k=i2+2; // branch not taken
        if (j==1) k=i2+2+(hcomp[i2+1]<<24>>24);  // branch taken
        for (int l=0; l<hlen && code; ++l) {  // trace at most hlen steps
          if (k<0 || k>=hlen) break;  // out of bounds, pass
          const int op=hcomp[k];
          if (op==39 || op==47) code=0;  // jt,jf, fail
          else if (op>=216 && op<240) break;  // ==,<,>, pass
          else if (iserr(op)) break;  // error, pass
          else if (op==255) k=hcomp[k+1]+256*hcomp[k+2]; // lj
          else if (op==63) k=k+2+(hcomp[k+1]<<24>>24);  // jmp
          else if (op==56) k=0;  // halt
          else k=k+1+(op%8==7);  // ordinary instruction
        }
      }
      it[i]+=code;  // if > 0 then OK to not save flags in f (bl)
    }
  }

  // Start of run(): Save x86 and load ZPAQL registers
  const int start=o;

  put1(0x56);          // push esi/rsi
  put1(0x57);          // push edi/rdi
  put1(0x53);          // push ebx/rbx
  put1(0x55);          // push ebp/rbp
  if (S==8) {
    put2(0x4154);      // push r12
    put2(0x4155);      // push r13
    put2(0x4156);      // push r14
    put2(0x4157);      // push r15
    put4(0x4883ec38);  // sub rsp, 56
    put2l(0x48b8, &a); // mov rax, a
    put2(0x8b10);      // mov edx, [rax]
    put2l(0x48b8, &b); // mov rax, b
    put2(0x8b30);      // mov esi, [rax]
    put2l(0x48b8, &c); // mov rax, c
    put2(0x8b38);      // mov edi, [rax]
    put2l(0x48b8, &d); // mov rax, d
    put2(0x8b28);      // mov ebp, [rax]
    put2l(0x48b8, &f); // mov rax, f
    put2(0x8b18);      // mov ebx, [rax]
    put2l(0x49bc, &h[0]);   // mov r12, h
    put2l(0x49bd, &outbuf[0]); // mov r13, outbuf.p
    put2l(0x49be, &r[0]);   // mov r14, r
    put2l(0x49bf, &m[0]);   // mov r15, m
  }
  else {
    put3(0x83ec3c);    // sub esp, 60
    put2a(0x8b15, &a); // mov edx, [a]
    put2a(0x8b35, &b); // mov esi, [b]
    put2a(0x8b3d, &c); // mov edi, [c]
    put2a(0x8b2d, &d); // mov ebp, [d]
    put2a(0x8b1d, &f); // mov ebx, [f]
  }

  // Assemble in multiple passes until every byte of hcomp has a translation
  for (int istart=0; istart<hlen; ++istart) {
    for (int i=istart; i<hlen&&it[i]; i=i+1+(hcomp[i]%8==7)+(hcomp[i]==255)) {
      const int code=it[i];

      // If already assembled, then assemble a jump to it
      U32 t;

      if (code>=16) {
        if (i>istart) {
          int a=code-o;
          if (a>-120 && a<120)
            put2(0xeb00+((a-2)&255)); // jmp short o
          else
            put1a(0xe9, a-5);  // jmp near o
        }
        break;
      }

      // Else assemble the instruction at hcode[i] to rcode[o]
      else {

        it[i]=o;
        ++done;
        const int op=hcomp[i];
        const int arg=hcomp[i+1]+((op==255)?256*hcomp[i+2]:0);
        const int ddd=op/8%8;
        const int sss=op%8;

        // error instruction: return 0
        if (iserr(op)) {
          put2(0x31c0);           // xor eax, eax
          put1a(0xe9, halt-o-4);  // jmp near halt
          continue;
        }

        // Load source *b, *c, *d, or hash (*b) into eax except:
        // {a,b,c,d}=*d, a{+,-,*,&,|,^,=,==,>,>}=*d: load address to eax
        // {a,b,c,d}={*b,*c}: load source into ddd
        if (op==59 || (op>=64 && op<240 && op%8>=4 && op%8<7)) {
          put2(0x89c0+8*regcode[sss-3+(op==59)]);  // mov eax, {esi,edi,ebp}
          const int sz=(sss==6?hsize:msize)-1;
          if (sz>=128) put1a(0x25, sz);            // and eax, dword msize-1
          else put3(0x83e000+sz);                  // and eax, byte msize-1
          const int move=(op>=64 && op<112); // = or else ddd is eax
          if (sss<6) { // ddd={a,b,c,d,*b,*c}
            if (S==8) put5(0x410fb604+8*move*regcode[ddd],0x07);
                                                   // movzx ddd, byte [r15+rax]
            else put3a(0x0fb680+8*move*regcode[ddd], &m[0]);
                                                   // movzx ddd, byte [m+eax]
          }
          else if ((0x06587000>>(op/8))&1) {// {*b,*c,*d,a/,a%,a&~,a<<,a>>}=*d
            if (S==8) put4(0x418b0484);            // mov eax, [r12+rax*4]
            else put3a(0x8b0485, &h[0]);           // mov eax, [h+eax*4]
          }
        }

        // Load destination address *b, *c, *d or hashd (*d) into ecx
        if ((op>=32 && op<56 && op%8<5) || (op>=96 && op<120) || op==60) {
          put2(0x89c1+8*regcode[op/8%8-3-(op==60)]);// mov ecx,{esi,edi,ebp}
          const int sz=(ddd==6||op==60?hsize:msize)-1;
          if (sz>=128) put2a(0x81e1, sz);   // and ecx, dword sz
          else put3(0x83e100+sz);           // and ecx, byte sz
          if (op/8%8==6 || op==60) { // *d
            if (S==8) put4(0x498d0c8c);     // lea rcx, [r12+rcx*4]
            else put3a(0x8d0c8d, &h[0]);    // lea ecx, [ecx*4+h]
          }
          else { // *b, *c
            if (S==8) put4(0x498d0c0f);     // lea rcx, [r15+rcx]
            else put2a(0x8d89, &m[0]);      // lea ecx, [ecx+h]
          }
        }

        // Code runs of up to 127 identical ++ or -- operations that are not
        // otherwise jump targets as a single instruction. Mark all but
        // the first as not reachable.
        int inc=0;  // run length of identical ++ or -- instructions
        if (op<=50 && (op%8==1 || op%8==2)) {
 
          inc=1;
          for (int j=i+1; inc<127 && j<hlen && it[j]==1 && hcomp[j]==op; ++j){
            ++inc;
            it[j]=0;
          }
        }

        // Translate by opcode
        switch((op/8)&31) {
          case 0:  // ddd = a
          case 1:  // ddd = b
          case 2:  // ddd = c
          case 3:  // ddd = d
            switch(sss) {
              case 0:  // ddd<>a (swap)
                put2(0x87d0+regcode[ddd]);   // xchg edx, ddd
                break;
              case 1:  // ddd++
                put3(0x83c000+256*regcode[ddd]+inc); // add ddd, inc
                break;
              case 2:  // ddd--
                put3(0x83e800+256*regcode[ddd]+inc); // sub ddd, inc
                break;
              case 3:  // ddd!
                put2(0xf7d0+regcode[ddd]);   // not ddd
                break;
              case 4:  // ddd=0
                put2(0x31c0+9*regcode[ddd]); // xor ddd,ddd
                break;
              case 7:  // ddd=r n
                if (S==8)
                  put3a(0x418b86+8*regcode[ddd], arg*4); // mov ddd, [r14+n*4]
                else
                  put2a(0x8b05+8*regcode[ddd], (&r[arg]));//mov ddd, [r+n]
                break;
            }
            break;
          case 4:  // ddd = *b
          case 5:  // ddd = *c
            switch(sss) {
              case 0:  // ddd<>a (swap)
                put2(0x8611);                // xchg dl, [ecx]
                break;
              case 1:  // ddd++
                put3(0x800100+inc);          // add byte [ecx], inc
                break;
              case 2:  // ddd--
                put3(0x802900+inc);          // sub byte [ecx], inc
                break;
              case 3:  // ddd!
                put2(0xf611);                // not byte [ecx]
                break;
              case 4:  // ddd=0
                put2(0x31c0);                // xor eax, eax
                put2(0x8801);                // mov [ecx], al
                break;
              case 7:  // jt, jf
              {
    
                static const unsigned char jtab[2][4]={{5,4,2,7},{4,5,3,6}};
                               // jnz,je,jb,ja, jz,jne,jae,jbe
                if (code<4) put2(0x84db);    // test bl, bl
                if (arg>=128 && arg-257-i>=0 && o-it[arg-257-i]<120)
                  put2(0x7000+256*jtab[op==47][code/4]); // jx short 0
                else
                  put2a(0x0f80+jtab[op==47][code/4], 0); // jx near 0
                break;
              }
            }
            break;
          case 6:  // ddd = *d
            switch(sss) {
              case 0:  // ddd<>a (swap)
                put2(0x8711);             // xchg edx, [ecx]
                break;
              case 1:  // ddd++
                put3(0x830100+inc);       // add dword [ecx], inc
                break;
              case 2:  // ddd--
                put3(0x832900+inc);       // sub dword [ecx], inc
                break;
              case 3:  // ddd!
                put2(0xf711);             // not dword [ecx]
                break;
              case 4:  // ddd=0
                put2(0x31c0);             // xor eax, eax
                put2(0x8901);             // mov [ecx], eax
                break;
              case 7:  // ddd=r n
                if (S==8)
                  put3a(0x418996, arg*4); // mov [r14+n*4], edx
                else
                  put2a(0x8915, &r[arg]); // mov [r+n], edx
                break;
            }
            break;
          case 7:  // special
            switch(op) {
              case 56: // halt
                put1a(0xb8, 1);           // mov eax, 1
                put1a(0xe9, halt-o-4);    // jmp near halt
                break;
              case 57:  // out
                put1a(0xe8, outlabel-o-4);// call outlabel
                break;
              case 59:  // hash: a = (a + *b + 512) * 773
                put3a(0x8d8410, 512);     // lea edx, [eax+edx+512]
                put2a(0x69d0, 773);       // imul edx, eax, 773
                break;
              case 60:  // hashd: *d = (*d + a + 512) * 773
                put2(0x8b01);             // mov eax, [ecx]
                put3a(0x8d8410, 512);     // lea eax, [eax+edx+512]
                put2a(0x69c0, 773);       // imul eax, eax, 773
                put2(0x8901);             // mov [ecx], eax
                break;
              case 63:  // jmp
                put1a(0xe9, 0);           // jmp near 0 (fill in target later)
                break;
            }
            break;
          case 8:   // a=
          case 9:   // b=
          case 10:  // c=
          case 11:  // d=
            if (sss==7)  // n
              put1a(0xb8+regcode[ddd], arg);         // mov ddd, n
            else if (sss==6) { // *d
              if (S==8)
                put4(0x418b0484+(regcode[ddd]<<11)); // mov ddd, [r12+rax*4]
              else
                put3a(0x8b0485+(regcode[ddd]<<11),&h[0]);// mov ddd, [h+eax*4]
            }
            else if (sss<4) // a, b, c, d
              put2(0x89c0+regcode[ddd]+8*regcode[sss]);// mov ddd,sss
            break;
          case 12:  // *b=
          case 13:  // *c=
            if (sss==7) put3(0xc60100+arg);          // mov byte [ecx], n
            else if (sss==0) put2(0x8811);           // mov byte [ecx], dl
            else {
              if (sss<4) put2(0x89c0+8*regcode[sss]);// mov eax, sss
              put2(0x8801);                          // mov byte [ecx], al
            }
            break;
          case 14:  // *d=
            if (sss<7) put2(0x8901+8*regcode[sss]);  // mov [ecx], sss
            else put2a(0xc701, arg);                 // mov dword [ecx], n
            break;
          case 15: break; // not used
          case 16:  // a+=
            if (sss==6) {
              if (S==8) put4(0x41031484);            // add edx, [r12+rax*4]
              else put3a(0x031485, &h[0]);           // add edx, [h+eax*4]
            }
            else if (sss<7) put2(0x01c2+8*regcode[sss]);// add edx, sss
            else if (arg>128) put2a(0x81c2, arg);    // add edx, n
            else put3(0x83c200+arg);                 // add edx, byte n
            break;
          case 17:  // a-=
            if (sss==6) {
              if (S==8) put4(0x412b1484);            // sub edx, [r12+rax*4]
              else put3a(0x2b1485, &h[0]);           // sub edx, [h+eax*4]
            }
            else if (sss<7) put2(0x29c2+8*regcode[sss]);// sub edx, sss
            else if (arg>=128) put2a(0x81ea, arg);   // sub edx, n
            else put3(0x83ea00+arg);                 // sub edx, byte n
            break;
          case 18:  // a*=
            if (sss==6) {
              if (S==8) put5(0x410faf14,0x84);       // imul edx, [r12+rax*4]
              else put4a(0x0faf1485, &h[0]);         // imul edx, [h+eax*4]
            }
            else if (sss<7) put3(0x0fafd0+regcode[sss]);// imul edx, sss
            else if (arg>=128) put2a(0x69d2, arg);   // imul edx, n
            else put3(0x6bd200+arg);                 // imul edx, byte n
            break;
          case 19:  // a/=
          case 20:  // a%=
            if (sss<7) put2(0x89c1+8*regcode[sss]);  // mov ecx, sss
            else put1a(0xb9, arg);                   // mov ecx, n
            put2(0x85c9);                            // test ecx, ecx
            put3(0x0f44d1);                          // cmovz edx, ecx
            put2(0x7408-2*(op/8==20));               // jz (over rest)
            put2(0x89d0);                            // mov eax, edx
            put2(0x31d2);                            // xor edx, edx
            put2(0xf7f1);                            // div ecx
            if (op/8==19) put2(0x89c2);              // mov edx, eax
            break;
          case 21:  // a&=
            if (sss==6) {
              if (S==8) put4(0x41231484);            // and edx, [r12+rax*4]
              else put3a(0x231485, &h[0]);           // and edx, [h+eax*4]
            }
            else if (sss<7) put2(0x21c2+8*regcode[sss]);// and edx, sss
            else if (arg>=128) put2a(0x81e2, arg);   // and edx, n
            else put3(0x83e200+arg);                 // and edx, byte n
            break;
          case 22:  // a&~
            if (sss==7) {
              if (arg<128) put3(0x83e200+(~arg&255));// and edx, byte ~n
              else put2a(0x81e2, ~arg);              // and edx, ~n
            }
            else {
              if (sss<4) put2(0x89c0+8*regcode[sss]);// mov eax, sss
              put2(0xf7d0);                          // not eax
              put2(0x21c2);                          // and edx, eax
            }
            break;
          case 23:  // a|=
            if (sss==6) {
              if (S==8) put4(0x410b1484);            // or edx, [r12+rax*4]
              else put3a(0x0b1485, &h[0]);           // or edx, [h+eax*4]
            }
            else if (sss<7) put2(0x09c2+8*regcode[sss]);// or edx, sss
            else if (arg>=128) put2a(0x81ca, arg);   // or edx, n
            else put3(0x83ca00+arg);                 // or edx, byte n
            break;
          case 24:  // a^=
            if (sss==6) {
              if (S==8) put4(0x41331484);            // xor edx, [r12+rax*4]
              else put3a(0x331485, &h[0]);           // xor edx, [h+eax*4]
            }
            else if (sss<7) put2(0x31c2+8*regcode[sss]);// xor edx, sss
            else if (arg>=128) put2a(0x81f2, arg);   // xor edx, byte n
            else put3(0x83f200+arg);                 // xor edx, n
            break;
          case 25:  // a<<=
          case 26:  // a>>=
            if (sss==7)  // sss = n
              put3(0xc1e200+8*256*(op/8==26)+arg);   // shl/shr n
            else {
              put2(0x89c1+8*regcode[sss]);           // mov ecx, sss
              put2(0xd3e2+8*(op/8==26));             // shl/shr edx, cl
            }
            break;
          case 27:  // a==
          case 28:  // a<
          case 29:  // a>
            if (sss==6) {
              if (S==8) put4(0x413b1484);            // cmp edx, [r12+rax*4]
              else put3a(0x3b1485, &h[0]);           // cmp edx, [h+eax*4]
            }
            else if (sss==7)  // sss = n
              put2a(0x81fa, arg);                    // cmp edx, dword n
            else
              put2(0x39c2+8*regcode[sss]);           // cmp edx, sss
            if (code<4) {
              if (op/8==27) put3(0x0f94c3);          // setz bl
              if (op/8==28) put3(0x0f92c3);          // setc bl
              if (op/8==29) put3(0x0f97c3);          // seta bl
            }
            break;
          case 30:  // not used
          case 31:  // 255 = lj
            if (op==255) put1a(0xe9, 0);             // jmp near
            break;
        }
        if (inc>1) {  // skip run of identical ++ or --
          i+=inc-1;
      
        }
      }
    }
  }

  // Finish first pass
  const int rsize=o;
  if (o>rcode_size) return rsize;

  // Fill in jump addresses (second pass)
  for (int i=0; i<hlen; ++i) {
    if (it[i]<16) continue;
    int op=hcomp[i];
    if (op==39 || op==47 || op==63 || op==255) {  // jt, jf, jmp, lj
      int target=hcomp[i+1];
      if (op==255) target+=hcomp[i+2]*256;  // lj
      else {
        if (target>=128) target-=256;
        target+=i+2;
      }
      if (target<0 || target>=hlen) target=hlen-1;  // runtime ZPAQL error
      o=it[i];
   
      if ((op==39 || op==47) && rcode[o]==0x84) o+=2;  // jt, jf -> skip test

      if (rcode[o]==0x0f) ++o;  // first byte of jz near, jnz near

      op=rcode[o++];  // x86 opcode
      target=it[target]-o;
      if ((op>=0x72 && op<0x78) || op==0xeb) {  // jx, jmp short
        --target;
        if (target<-128 || target>127)
          error("Cannot code x86 short jump");
  
        rcode[o]=target&255;
      }
      else if ((op>=0x82 && op<0x88) || op==0xe9) // jx, jmp near
      {
        target-=4;
        puta(target);
      }
      else 
		exit(0);
    }
  }

  // Jump to start
  o=0;
  put1a(0xe9, start-5);  // jmp near start
  return rsize;
}

//////////////////////// Predictor::assemble_p() /////////////////////

// Assemble the ZPAQL code in the HCOMP section of z.header to pcomp and
// return the number of bytes of x86 or x86-64 code written, or that would
// be written if pcomp were large enough. The code for predict() begins
// at pr.pcomp[0] and update() at pr.pcomp[5], both as jmp instructions.

// The assembled code is equivalent to int predict(Predictor*)
// and void update(Predictor*, int y); The Preditor address is placed in
// edi/rdi. The update bit y is placed in ebp/rbp.

int Predictor::assemble_p() 
{
	return 0;
}

#endif // ifndef NOJIT

// Return a prediction of the next bit in range 0..32767
// Use JIT code starting at pcode[0] if available, or else create it.
int Predictor::predict() {
#ifdef NOJIT
  return predict0();
#else
  if (!pcode) {
    allocx(pcode, pcode_size, (z.cend*100+4096)&-4096);
    int n=assemble_p();
    if (n>pcode_size) {
      allocx(pcode, pcode_size, n);
      n=assemble_p();
    }
    if (!pcode || n<15 || pcode_size<15)
      error("run JIT failed");
  }

  return ((int(*)(Predictor*))&pcode[10])(this);
#endif
}

// Update the model with bit y = 0..1
// Use the JIT code starting at pcode[5].
void Predictor::update(int y) {
#ifdef NOJIT
  update0(y);
#else

  ((void(*)(Predictor*, int))&pcode[5])(this, y);

  // Save bit y in c8, hmap4 (not implemented in JIT)
  c8+=c8+y;
  if (c8>=256) {
    z.run(c8-256);
    hmap4=1;
    c8=1;
    for (int i=0; i<z.header[6]; ++i) h[i]=z.H(i);
  }
  else if (c8>=16 && c8<32)
    hmap4=(hmap4&0xf)<<5|y<<4|1;
  else
    hmap4=(hmap4&0x1f0)|(((hmap4&0xf)*2+y)&0xf);
#endif
}

// Execute the ZPAQL code with input byte or -1 for EOF.
// Use JIT code at rcode if available, or else create it.
void ZPAQL::run(U32 input) {
#ifdef NOJIT
  run0(input);
#else
  if (!rcode) {
    allocx(rcode, rcode_size, (hend*10+4096)&-4096);
    int n=assemble();
    if (n>rcode_size) {
      allocx(rcode, rcode_size, n);
      n=assemble();
    }
    if (!rcode || n<10 || rcode_size<10)
      error("run JIT failed");
  }
  a=input;
  if (!((int(*)())(&rcode[0]))())
    libzpaq::error("Bad ZPAQL opcode");
#endif
}

}  // end namespace libzpaq






using std::string;
using std::vector;
using std::map;

// Handle errors in libzpaq and elsewhere
void libzpaq::error(const char* msg) {
  fprintf(stderr, "zpaqlist error: %s\n", msg);
  exit(0);
}
using libzpaq::error;


// C++ strings are cute, but very slow. Let's go back to C
inline char *  migliaia(uint64_t n)
{
	static char retbuf[30];
	char *p = &retbuf[sizeof(retbuf)-1];
	unsigned int i = 0;
	*p = '\0';
	do 
	{
		if(i%3 == 0 && i != 0)
			*--p = '.';
		*--p = '0' + n % 10;
		n /= 10;
		i++;
		} while(n != 0);
	return p;
}
inline char *  migliaia2(uint64_t n)
{
	static char retbuf[30];
	char *p = &retbuf[sizeof(retbuf)-1];
	unsigned int i = 0;
	*p = '\0';
	do 
	{
		if(i%3 == 0 && i != 0)
			*--p = '.';
		*--p = '0' + n % 10;
		n /= 10;
		i++;
		} while(n != 0);
	return p;
}


// Global variables
int64_t list_g_dimensione=0;

FILE* list_outputlog=stdout;
FILE* list_con=stdout;    // log output, can be stderr
int64_t list_quiet=-1;    // -list_quiet option
static const int64_t LIST_MAX_QUIET=0x7FFFFFFFFFFFFFFFLL;  // no output but errors
int64_t list_global_start=0;  // set to mtime() at start of main()

// signed size of a string or vector
template <typename T> int list_size(const T& x) {
  return x.size();
}

// In Windows, convert 16-bit wide string to UTF-8 and \ to /
string list_wtou(const wchar_t* s) {

  string r;
  if (!s) return r;
  for (; *s; ++s) {
    if (*s=='\\') r+='/';
    else if (*s<128) r+=*s;
    else if (*s<2048) r+=192+*s/64, r+=128+*s%64;
    else r+=224+*s/4096, r+=128+*s/64%64, r+=128+*s%64;
  }
  return r;
}

// In Windows, convert UTF-8 string to wide string ignoring
// invalid UTF-8 or >64K. If doslash then convert "/" to "\".
std::wstring list_utow(const char* ss, bool doslash=false) {


  std::wstring r;
  if (!ss) return r;
  const unsigned char* s=(const unsigned char*)ss;
  for (; s && *s; ++s) {
    if (s[0]=='/' && doslash) r+='\\';
    else if (s[0]<128) r+=s[0];
    else if (s[0]>=192 && s[0]<224 && s[1]>=128 && s[1]<192)
      r+=(s[0]-192)*64+s[1]-128, ++s;
    else if (s[0]>=224 && s[0]<240 && s[1]>=128 && s[1]<192
             && s[2]>=128 && s[2]<192)
      r+=(s[0]-224)*4096+(s[1]-128)*64+s[2]-128, s+=2;
  }
  return r;
}

// Print a UTF-8 string to f (stdout, stderr) so it displays properly
void list_printutf8(const char* s, FILE* f) {

  const HANDLE h=(HANDLE)_get_osfhandle(_fileno(f));
  DWORD ft=GetFileType(h);
  if (ft==FILE_TYPE_CHAR) {
    fflush(f);
    std::wstring w=list_utow(s);  // Windows console: convert to UTF-16
    DWORD n=0;
    WriteConsole(h, w.c_str(), w.size(), &n, 0);
  }
  else  // stdout redirected to file
    fprintf(f, "%s", s);
}

// Return relative time in milliseconds
int64_t list_mtime() {
  int64_t t=GetTickCount();
  if (t<list_global_start) t+=0x100000000LL;
  return t;
}

// Convert 64 bit decimal YYYYMMDDHHMMSS to "YYYY-MM-DD HH:MM:SS"
// where -1 = unknown date, 0 = deleted.
string list_dateToString(int64_t date) {
  if (date<=0) return "                   ";
  string s="0000-00-00 00:00:00";
  static const int t[]={18,17,15,14,12,11,9,8,6,5,3,2,1,0};
  for (int i=0; i<14; ++i) s[t[i]]+=int(date%10), date/=10;
  return s;
}
string list_mydateToString(int64_t date) {
  if (date<=0) return "                   ";
  ///        0123456789012345678
  string  s="0000-00-00 00:00:00";
  string s2="00/00/0000 00:00:00";
  
  
  static const int t[]={18,17,15,14,12,11,9,8,6,5,3,2,1,0};
  for (int i=0; i<14; ++i) s[t[i]]+=int(date%10), date/=10;

/// convert in european date format dd/mm/yyyy hh:mm:ss
  s2[0]=s[8];
  s2[1]=s[9];
  s2[3]=s[5];
  s2[4]=s[6];
  s2[6]=s[0];
  s2[7]=s[1];
  s2[8]=s[2];
  s2[9]=s[3];
  
  s2[11]=s[11];
  s2[12]=s[12];
  
  s2[14]=s[14];
  s2[15]=s[15];
  
  s2[17]=s[17];
  s2[18]=s[18];
  return s2;
}



/////////////////////////////// File //////////////////////////////////

// Convert non-negative decimal number x to string of at least n digits
string list_itos(int64_t x, int n=1) {

  string r;
  for (; x || n>0; x/=10, --n) r=string(1, '0'+x%10)+r;
  return r;
}

// Replace * and ? in fn with part or digits of part
string list_subpart(string fn, int part) {
  for (int j=fn.size()-1; j>=0; --j) {
    if (fn[j]=='?')
      fn[j]='0'+part%10, part/=10;
    else if (fn[j]=='*')
      fn=fn.substr(0, j)+list_itos(part)+fn.substr(j+1), part=0;
  }
  return fn;
}

// Return true if a file or directory (UTF-8 without trailing /) list_exists.
// If part>0 then replace * and ? in filename with part or its digits.
bool list_exists(string filename, int part=0) {
  if (part>0) filename=list_subpart(filename, part);
  int len=filename.size();
  if (len<1) return false;
  if (filename[len-1]=='/') filename=filename.substr(0, len-1);
  return GetFileAttributes(list_utow(filename.c_str(), true).c_str())
         !=INVALID_FILE_ATTRIBUTES;
}


// Print error message
void list_printerr(const char* filename) {
  int err=GetLastError();
  list_printutf8(filename, stderr);
  if (err==ERROR_FILE_NOT_FOUND)
    fprintf(stderr, ": file not found\n");
  else if (err==ERROR_PATH_NOT_FOUND)
    fprintf(stderr, ": path not found\n");
  else if (err==ERROR_ACCESS_DENIED)
    fprintf(stderr, ": access denied\n");
  else if (err==ERROR_SHARING_VIOLATION)
    fprintf(stderr, ": sharing violation\n");
  else if (err==ERROR_BAD_PATHNAME)
    fprintf(stderr, ": bad pathname\n");
  else if (err==ERROR_INVALID_NAME)
    fprintf(stderr, ": invalid name\n");
  else
    fprintf(stderr, ": Windows error %d\n", err);
}

// Base class of InputFile and list_OutputFile (OS independent)
class list_File {
protected:
  enum {BUFSIZE=1<<16};  // buffer size
  int ptr;  // next byte to read or write in buf
  libzpaq::Array<char> buf;  // I/O buffer
  libzpaq::AES_CTR *aes;  // if not NULL then encrypt
  int64_t eoff;  // extra offset for multi-file encryption
  list_File(): ptr(0), buf(BUFSIZE), aes(0), eoff(0) {}
};

// list_File types accepting UTF-8 filenames

class list_InputFile: public list_File, public libzpaq::Reader {
  HANDLE in;  // input file handle
  DWORD n;    // buffer size
public:
  list_InputFile():
    in(INVALID_HANDLE_VALUE), n(0) {}

  // Open for reading. Return true if successful.
  // Encrypt with aes+e if aes.
  bool open(const char* filename, libzpaq::AES_CTR* a=0, int64_t e=0) {

    n=ptr=0;
    std::wstring w=list_utow(filename, true);
    in=CreateFile(w.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (in==INVALID_HANDLE_VALUE) list_printerr(filename);
    aes=a;
    eoff=e;
    return in!=INVALID_HANDLE_VALUE;
  }

  bool isopen() {return in!=INVALID_HANDLE_VALUE;}

  // Read 1 byte
  int get() {
    if (ptr>=int(n)) {

      ptr=0;
      ReadFile(in, &buf[0], BUFSIZE, &n, NULL);
      if (n==0) return EOF;
      if (aes) {
        int64_t off=tell()+eoff;
        if (off<32) error("attempt to read salt");
        aes->encrypt(&buf[0], n, off);
      }
    }

    return buf[ptr++]&255;
  }

  // set file pointer
  void seek(int64_t pos, int whence) {
    if (whence==SEEK_SET) whence=FILE_BEGIN;
    else if (whence==SEEK_END) whence=FILE_END;
    else if (whence==SEEK_CUR) {
      whence=FILE_BEGIN;
      pos+=tell();
    }
    long offhigh=pos>>32;
    SetFilePointer(in, pos, &offhigh, whence);
    n=ptr=0;
  }

  // get file pointer
  int64_t tell() {
    long offhigh=0;
    DWORD r=SetFilePointer(in, 0, &offhigh, FILE_CURRENT);
    return (int64_t(offhigh)<<32)+r+ptr-n;
  }

  // Close handle if open
  void close() {
    if (in!=INVALID_HANDLE_VALUE) {
      CloseHandle(in);
      in=INVALID_HANDLE_VALUE;
    }
  }
  ~list_InputFile() {close();}
};


/////////////////////////////// list_Archive ///////////////////////////////

// An list_Archive is a multi-part file that supports encrypted input
class list_Archive: public libzpaq::Reader, public libzpaq::Writer {
  libzpaq::AES_CTR* aes;  // NULL if not encrypted
  struct FE {  // list_File element for multi-part archives
    string fn;    // file name
    int64_t end;  // size of previous and current files
    FE(): end(0) {}
    FE(const string& s, int64_t e): fn(s), end(e) {}
  };
  vector<FE> files;  // list of parts. only last part is writable.
  int fi;  // current file in files
  int64_t off;  // total offset over all files
  int mode;     // 'r' or 'w' for reading or writing or 0 if closed
  list_InputFile in; // currently open input file
///  list_OutputFile out;  // currently open output file
public:

  // Constructor
  list_Archive(): aes(0), fi(0), off(0), mode(0) {}

  // Destructor
  ~list_Archive() {close();}

  // Open filename for read and write. If filename contains wildards * or ?
  // then replace * with part number 1, 2, 3... or ? with single digits
  // up to the last existing file. Return true if at least one file is found.
  // If password is not NULL then assume the concatenation of the files
  // is in encrypted format. mode_ is 'r' for reading or 'w' for writing.
  // If the filename contains wildcards then output is to the first
  // non-existing file, else to filename. If newsize>=0 then truncate
  // the output to newsize bytes. If password and offset>0 then encrypt
  // output as if previous parts had size offset and salt salt.
  bool open(const char* filename, const char* password=0, int mode_='r',
            int64_t newsize=-1, int64_t offset=0, const char* salt=0);

  // True if archive is open
  bool isopen() const {return files.size()>0;}

  // Position the next read or write offset to p.
  void seek(int64_t p, int whence);

  // Return current file offset.
  int64_t tell() const {return off;}

  // Read up to n bytes into buf at current offset. Return 0..n bytes
  // actually read. 0 indicates EOF.
  int read(char* buf, int n) {

    if (fi>=list_size(files)) return 0;
    if (!in.isopen()) return 0;
    n=in.read(buf, n);
    seek(n, SEEK_CUR);
    return n;
  }

  // Read and return 1 byte or -1 (EOF)
  int get() {

    if (fi>=list_size(files)) return -1;
    while (off==files[fi].end) {
      in.close();
      if (++fi>=list_size(files)) return -1;
      if (!in.open(files[fi].fn.c_str(), aes, fi>0 ? files[fi-1].end : 0))
        error("cannot read next archive part");
    }
    ++off;
    return in.get();
  }

  // Write one byte
  void put(int c) {
    c+=3; /// nowarning please
	++off;
  }

  // Write buf[0..n-1]

  // Close any open part
  void close() {
    if (in.isopen()) in.close();
    if (aes) {
      delete aes;
      aes=0;
    }
    files.clear();
    fi=0;
    off=0;
    mode=0;
  }
};


void list_print_datetime(void)
{
	int hours, minutes, seconds, day, month, year;

	time_t now;
	time(&now);
	struct tm *local = localtime(&now);

	hours = local->tm_hour;			// get hours since midnight	(0-23)
	minutes = local->tm_min;		// get minutes passed after the hour (0-59)
	seconds = local->tm_sec;		// get seconds passed after the minute (0-59)

	day = local->tm_mday;			// get day of month (1 to 31)
	month = local->tm_mon + 1;		// get month of year (0 to 11)
	year = local->tm_year + 1900;	// get year since 1900

	printf("%02d/%02d/%d %02d:%02d:%02d ", day, month, year, hours,minutes,seconds);

}

 
 
bool list_Archive::open(const char* filename, const char* password, int mode_,
                   int64_t newsize, int64_t offset, const char* salt) {

  mode=mode_;

  list_g_dimensione=0;
  
  // Read part files and get sizes. Get salt from the first part.
  string next;

  int64_t startscan=list_mtime();
  int i;
  for (i=1; !offset; ++i) 
  {
    next=list_subpart(filename, i);
    
	if (!list_exists(next)) break;
    if (files.size()>0 && files[0].fn==next) break; // part overflow
	
    // set up key from salt in first file
    if (!in.open(next.c_str())) error("cannot read archive");
    if (i==1 && password && newsize!=0) {
      char slt[32], key[32];
      if (in.read(slt, 32)!=32) error("no salt");
      libzpaq::stretchKey(key, password, slt);
      aes=new libzpaq::AES_CTR(key, 32, slt);
    }

	
    // Get file size
    in.seek(0, SEEK_END);
    files.push_back(FE(next,
        in.tell()+(files.size() ? files[files.size()-1].end : 0)));
    
	list_g_dimensione+=in.tell();
	in.close();
    if (next==filename) break;  // no wildcards
  }
	list_print_datetime();
	printf("Multipart scan %f s chunks %d\n",(list_mtime()-startscan)/1000.0,i);
 	
  // If offset is not 0 then use it for the part sizes and use
  // salt as the salt of the first part.
  if (offset>0) {
    files.push_back(FE("", offset));
    files.push_back(FE(filename, offset));
    if (password) {

      char key[32]={0};
      libzpaq::stretchKey(key, password, salt);
      aes=new libzpaq::AES_CTR(key, 32, salt);
    }
  }

  // Open file for reading
  fi=files.size();
  if (mode=='r') {
    seek(32*(password!=0), SEEK_SET);  // open first input file
    return files.size()>0;
  }
	return false;
}

void list_Archive::seek(int64_t p, int whence) {
  if (whence==SEEK_SET) off=p;
  else if (whence==SEEK_CUR) off+=p;
  else if (whence==SEEK_END) off=(files.size() ? files.back().end : 0)+p;
  else exit(0);
  if (mode=='r') {
    int oldfi=fi;
    for (fi=0; fi<list_size(files) && off>=files[fi].end; ++fi);
    if (fi!=oldfi) {
      in.close();
      if (fi<list_size(files) && !in.open(files[fi].fn.c_str(), aes,
          fi>0 ? files[fi-1].end : 0))
        error("cannot reopen archive after seek");
    }
    if (fi<list_size(files)) in.seek(off-files[fi].end, SEEK_END);
  }
}

///////////////////////// NumberOfProcessors ///////////////////////////

// Guess number of cores. In 32 bit mode, max is 2.
int list_numberOfProcessors() {
  int rc=0;  // result
  // In Windows return %NUMBER_OF_PROCESSORS%
  const char* p=getenv("NUMBER_OF_PROCESSORS");
  if (p) rc=atoi(p);
  if (rc<1) rc=1;
  if (sizeof(char*)==4 && rc>2) rc=2;
  return rc;
}

////////////////////////////// StringBuffer //////////////////////////

// For libzpaq output to a string
struct list_StringWriter: public libzpaq::Writer {
  string s;
  void put(int c) {s+=char(c);}
};



// For (de)compressing to/from a string. Writing appends bytes
// which can be later read.
class list_StringBuffer: public libzpaq::Reader, public libzpaq::Writer {
  unsigned char* p;  // allocated memory, not NUL terminated, may be NULL
  size_t al;         // number of bytes allocated, 0 iff p is NULL
  size_t wpos;       // index of next byte to write, wpos <= al
  size_t rpos;       // index of next byte to read, rpos < wpos or return EOF.
  size_t limit;      // max size, default = -1
  const size_t init; // initial size on first use after reset

  // Increase capacity to a without changing size
  void reserve(size_t a) {

    if (a<=al) return;
    unsigned char* q=0;
    if (a>0) q=(unsigned char*)(p ? realloc(p, a) : malloc(a));
    if (a>0 && !q) {
      printf( "list_StringBuffer realloc %1.0f to %1.0f at %p failed\n",
          double(al), double(a), p);
      error("Out of memory");
    }
    p=q;
    al=a;
  }

  // Enlarge al to make room to write at least n bytes.
  void lengthen(unsigned n) {

    if (wpos+n>limit) error("list_StringBuffer overflow");
    if (wpos+n<=al) return;
    size_t a=al;
    while (wpos+n>=a) a=a*2+init;
    reserve(a);
  }

  // No assignment or copy
  void operator=(const list_StringBuffer&);
  list_StringBuffer(const list_StringBuffer&);

public:

  // Direct access to data
  unsigned char* data() {return p;}

  // Allocate no memory initially
  list_StringBuffer(size_t n=0):
      p(0), al(0), wpos(0), rpos(0), limit(size_t(-1)), init(n>128?n:128) {}

  // Set output limit
  void setLimit(size_t n) {limit=n;}

  // Free memory
  ~list_StringBuffer() {if (p) free(p);}

  // Return number of bytes written.
  size_t size() const {return wpos;}

  // Return number of bytes left to read
  size_t remaining() const {return wpos-rpos;}

  // Reset size to 0.
  void reset() {
    if (p) free(p);
    p=0;
    al=rpos=wpos=0;
  }

  // Write a single byte.
  void put(int c) {  // write 1 byte
    lengthen(1);

    p[wpos++]=c;
  }

  // Write buf[0..n-1]
  void write(const char* buf, int n) {
    if (n<1) return;
    lengthen(n);
    memcpy(p+wpos, buf, n);
    wpos+=n;
  }

  // Read a single byte. Return EOF (-1) and reset at end of string.
  int get() {

    return rpos<wpos ? p[rpos++] : (reset(),-1);
  }

  // Read up to n bytes into buf[0..] or fewer if EOF is first.
  // Return the number of bytes actually read.
  int read(char* buf, int n) {

    if (rpos+n>wpos) n=wpos-rpos;
    if (n>0) memcpy(buf, p+rpos, n);
    rpos+=n;
    return n;
  }

  // Return the entire string as a read-only array.
  const char* c_str() const {return (const char*)p;}

  // Truncate the string to size i.
  void resize(size_t i) {wpos=i;}

  // Write a string.
  void operator+=(const string& t) {write(t.data(), t.size());}

  // Swap efficiently (init is not swapped)
  void swap(list_StringBuffer& s) {
    std::swap(p, s.p);
    std::swap(al, s.al);
    std::swap(wpos, s.wpos);
    std::swap(rpos, s.rpos);
    std::swap(limit, s.limit);
  }
};

////////////////////////////// misc ///////////////////////////////////

// In Windows convert upper case to lower case.
inline int list_tolowerW(int c) {
#ifndef unix
  if (c>='A' && c<='Z') return c-'A'+'a';
#endif
  return c;
}

// Return true if strings a == b or a+"/" is a prefix of b
// or a ends in "/" and is a prefix of b.
// Match ? in a to any char in b.
// Match * in a to any string in b.
// In Windows, not case sensitive.
bool list_ispath(const char* a, const char* b) {
  for (; *a; ++a, ++b) {
    const int ca=list_tolowerW(*a);
    const int cb=list_tolowerW(*b);
    if (ca=='*') {
      while (true) {
        if (list_ispath(a+1, b)) return true;
        if (!*b) return false;
        ++b;
      }
    }
    else if (ca=='?') {
      if (*b==0) return false;
    }
    else if (ca==cb && ca=='/' && a[1]==0)
      return true;
    else if (ca!=cb)
      return false;
  }
  return *b==0 || *b=='/';
}

// Convert string to lower case
string list_lowercase(string s) {
  for (unsigned i=0; i<s.size(); ++i)
    if (s[i]>='A' && s[i]<='Z') s[i]+='a'-'A';
  return s;
}

// Read 4 byte little-endian int and advance s
int list_btoi(const char* &s) {
  s+=4;
  return (s[-4]&255)|((s[-3]&255)<<8)|((s[-2]&255)<<16)|((s[-1]&255)<<24);
}

// Read 8 byte little-endian int and advance s
int64_t list_btol(const char* &s) {
  int64_t r=unsigned(list_btoi(s));
  return r+(int64_t(list_btoi(s))<<32);
}

// Convert x to 4 byte little-endian string
string list_itob(unsigned x) {
  string s(4, '\0');
  s[0]=x, s[1]=x>>8, s[2]=x>>16, s[3]=x>>24;
  return s;
}

// convert to 8 byte little-endian string
string list_ltob(int64_t x) {
  string s(8, '\0');
  s[0]=x,     s[1]=x>>8,  s[2]=x>>16, s[3]=x>>24;
  s[4]=x>>32, s[5]=x>>40, s[6]=x>>48, s[7]=x>>56;
  return s;
}

// Convert decimal, octal (leading o) or hex (leading x) string to int
int list_ntoi(const char* s) {
  int n=0, base=10, sign=1;
  for (; *s; ++s) {
    int c=*s;
    if (isupper(c)) c=tolower(c);
    if (!n && c=='x') base=16;
    else if (!n && c=='o') base=8;
    else if (!n && c=='-') sign=-1;
    else if (c>='0' && c<='9') n=n*base+c-'0';
    else if (base==16 && c>='a' && c<='f') n=n*base+c-'a'+10;
    else break;
  }
  return n*sign;
}

/////////////////////////// read_password ////////////////////////////

// Read a password from argv[i+1..argc-1] or from the console without
// echo (repeats times) if this sequence is empty. repeats can be 1 or 2.
// If 2, require the same password to be entered twice in a row.
// Advance i by the number of words in the password on the command
// line, which will be 0 if the user is prompted.
// Write the SHA-256 hash of the password in hash[0..31].
// Return the length of the original password.

int list_read_password(char* hash, int repeats,
                 int argc, const char** argv, int& i) {

  libzpaq::SHA256 sha256;
  int result=0;

  // Read password from argv[i+1..argc-1]
  if (i<argc-1 && argv[i+1][0]!='-') {
    while (true) {  // read multi-word password with spaces between args
      ++i;
      for (const char* p=argv[i]; p && *p; ++p) sha256.put(*p);
      if (i<argc-1 && argv[i+1][0]!='-') sha256.put(' ');
      else break;
    }
    result=sha256.usize();
    memcpy(hash, sha256.result(), 32);
    return result;
  }

  // Otherwise prompt user
  char oldhash[32]={0};
  if (repeats==2)
    printf( "Enter new password twice:\n");
  else {
    printf( "Password: ");
    fflush(stderr);
  }
  do {

  // Read password without echo to end of line
    HANDLE h=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0, n=0;
    wchar_t buf[256];
    if (h!=INVALID_HANDLE_VALUE
        && GetConsoleMode(h, &mode)
        && SetConsoleMode(h, mode&~ENABLE_ECHO_INPUT)
        && ReadConsole(h, buf, 250, &n, NULL)) {
      SetConsoleMode(h, mode);
      printf( "\n");
      for (unsigned i=0; i<n && i<250 && buf[i]!=10 && buf[i]!=13; ++i)
        sha256.put(buf[i]);
    }
    else {
      printf( "Windows error %d\n", int(GetLastError()));
      error("Read password failed");
    }
    result=sha256.usize();
    memcpy(oldhash, hash, 32);
    memcpy(hash, sha256.result(), 32);
    memset(buf, 0, sizeof(buf));  // clear sensitive data
  }
  while (repeats==2 && memcmp(oldhash, hash, 32));
  return result;
}

/////////////////////////////// Jidac /////////////////////////////////

// A Jidac object represents an archive contents: a list of file
// fragments with hash, size, and archive offset, and a list of
// files with date, attributes, and list of fragment pointers.
// Methods add to, extract from, compare, and list the archive.

// enum for list_HT::csize and version
static const int64_t LIST_EXTRACTED= 0x7FFFFFFFFFFFFFFELL;  // decompressed?
static const int64_t LIST_HT_BAD=   -0x7FFFFFFFFFFFFFFALL;  // no such frag
static const int64_t LIST_DEFAULT_VERSION=99999999999999LL; // unless -until

// fragment hash table entry
struct list_HT {
  unsigned char sha1[20];  // fragment hash
  int usize;      // uncompressed size, -1 if unknown
  int64_t csize;  // if >=0 then block offset else -fragment number
  list_HT(const char* s=0, int u=-1, int64_t c=LIST_HT_BAD) {
    if (s) memcpy(sha1, s, 20);
    else memset(sha1, 0, 20);
    usize=u; csize=c;
  }
};

// filename version entry
struct list_DTV {
  int64_t date;          // decimal YYYYMMDDHHMMSS (UT) or 0 if deleted
  int64_t size;          // size or -1 if unknown
  int64_t attr;          // first 8 attribute bytes
  double csize;          // approximate compressed size
  vector<unsigned> ptr;  // list of fragment indexes to list_HT
  int version;           // which transaction was it added?
  list_DTV(): date(0), size(0), attr(0), csize(0), version(0) {}
};

// filename entry
struct list_DT {
  int64_t edate;         // date of external file, 0=not found
  int64_t esize;         // size of external file
  int64_t eattr;         // external file attributes ('u' or 'w' in low byte)
  uint64_t sortkey;      // determines sort order for compression
  vector<unsigned> eptr; // fragment list of external file to add
  vector<list_DTV> dtv;       // list of versions
  int written;           // 0..ptr.size() = fragments output. -1=ignore
  list_DT(): edate(0), esize(0), eattr(0), sortkey(0), written(-1) {}
};
typedef map<string, list_DT> list_DTMap;

// Version info
struct list_VER {
  int64_t date;          // 0 if not JIDAC
  int64_t usize;         // uncompressed size of files
  int64_t offset;        // start of transaction
  int64_t csize;         // size of compressed data, -1 = no index
  int updates;           // file updates
  int deletes;           // file deletions
  unsigned firstFragment;// first fragment ID
  list_VER() {memset(this, 0, sizeof(*this));}
};


// Do everything
class list_Jidac {
public:
  int doCommand(int argc, const char** argv);
private:

  // Command line arguments
  string command;           // 
  string archive;           // archive name
  string fileoutput;
  vector<string> files;     // filename args
  bool all;                 // -all option
  bool distinct;			// -distinct option
  bool pakka;				// verbose output
  char password_string[32]; // hash of -key argument
  const char* password;     // points to password_string or NULL
  int threads;              // default is number of cores
  int64_t date;             // now as decimal YYYYMMDDHHMMSS (UT)
  int64_t version;          // version number or 14 digit date
  
  // list_Archive state
  int64_t dhsize;           // total size of D blocks according to H blocks
  int64_t dcsize;           // total size of D blocks according to C blocks
  vector<list_HT> ht;            // list of fragments
  list_DTMap dt;                 // set of files
  vector<list_VER> ver;          // version info

  // Commands
  int mylist();				// list, deduplicated
  void usage();             // help

  // Support functions
  int64_t list_read_archive(int *errors=0, const char* arc=0);  // read arc
};


// Print help message
void list_Jidac::usage() 
{
	printf("List zpaq archive in 'deduplicated' list\n\n");
	printf("GitHub            : https://sourceforge.net/projects/zpaqlist\n");
	printf("\n");
	printf("Mandatory command : l\n");
	printf("Optional switches : -distinct,-pakka,-all,-key password,-until version,-out logfile.txt\n");
	printf("\n");
	printf("Ex : zpaqlist l h:\\zarc\\1.zpaq -out z:\\default.txt\n");
	printf("Ex : zpaqlist l h:\\zarc\\1.zpaq -all -distinct -out z:\\default.txt\n");
	printf("   : zpaqlist l h:\\zarc\\1.zpaq -all -out z:\\all.txt\n");
	printf("   : zpaqlist l h:\\zarc\\1.zpaq -until 10 -out z:\\10.txt\n");



  exit(1);
}


// Expand an abbreviated option (with or without a leading "-")
// or report error if not exactly 1 match. Always expand commands.
string list_expandOption(const char* opt) {
  const char* opts[]={
    "list","distinct","out","pakka",
    "all","key",	  
    "until",0};

  if (opt[0]=='-') ++opt;
  const int n=strlen(opt);
  string result;
  for (unsigned i=0; opts[i]; ++i) {
    if (!strncmp(opt, opts[i], n)) {
      if (result!="")
        printf( "Ambiguous: %s\n", opt), exit(1);
      result=string("-")+opts[i];
      if (i<4 && result!="") return result;
    }
  }
  if (result=="")
    printf( "No such option: %s\n", opt), exit(1);
  return result;
}


// Parse the command line. Return 1 if error else 0.
int list_Jidac::doCommand(int argc, const char** argv) {

  // initialize options to default values
  command="";
  all=false;
  password=0;  // no password
  list_quiet=-1; // global
  distinct=false; //skip same file
  pakka=false;
  threads=0; // 0 = auto-detect
  version=LIST_DEFAULT_VERSION;
  date=0;
  
  // Init archive state
  ht.resize(1);  // element 0 not used
  ver.resize(1); // version 0
  dhsize=dcsize=0;

  // Get date
  time_t now=time(NULL);
  tm* t=gmtime(&now);
  date=(t->tm_year+1900)*10000000000LL+(t->tm_mon+1)*100000000LL
      +t->tm_mday*1000000+t->tm_hour*10000+t->tm_min*100+t->tm_sec;

  // Get optional options
  for (int i=1; i<argc; ++i) {
    const string opt=list_expandOption(argv[i]);  // read command
     if ((opt=="-list")
        && i<argc-1 && argv[i+1][0]!='-' && command=="") {
      archive=argv[++i];
      if (archive!="" &&   // Add .zpaq extension
          (list_size(archive)<5 || archive.substr(archive.size()-5)!=".zpaq"))
         archive+=".zpaq";
      command=opt;
      while (++i<argc && argv[i][0]!='-')
        files.push_back(argv[i]);
      --i;
    }
    else if (opt=="-all") all=true;
	else if (opt=="-out")
	{
		if (fileoutput=="" && strlen(argv[i+1])>=5)
		{
			fileoutput=argv[i+1];
			i++;
		}
	}
    else if (opt=="-distinct") distinct=true;
	else if (opt=="-pakka") pakka=true;
	
    else if (opt=="-key") {
      if (list_read_password(password_string, 2-list_exists(archive, 1),
          argc, argv, i))
        password=password_string;
    }
    else if (opt=="-until" && i+1<argc) {  // read date

      // Read digits from multiple args and fill in leading zeros
      version=0;
      int digits=0;
      if (argv[i+1][0]=='-') {  // negative version
        version=atol(argv[i+1]);
        if (version>-1) usage();
        ++i;
      }
      else {  // positive version or date
        while (++i<argc && argv[i][0]!='-') {
          for (int j=0; ; ++j) {
            if (isdigit(argv[i][j])) {
              version=version*10+argv[i][j]-'0';
              ++digits;
            }
            else {
              if (digits==1) version=version/10*100+version%10;
              digits=0;
              if (argv[i][j]==0) break;
            }
          }
        }
        --i;
      }

      // Append default time
      if (version>=19000000LL     && version<=29991231LL)
        version=version*100+23;
      if (version>=1900000000LL   && version<=2999123123LL)
        version=version*100+59;
      if (version>=190000000000LL && version<=299912312359LL)
        version=version*100+59;
      if (version>9999999) {
        if (version<19000101000000LL || version>29991231235959LL) {
          printf(
            "Version date %1.0f must be 19000101000000 to 29991231235959\n",
             double(version));
          exit(1);
        }
        date=version;
      }
    }

    else
      usage();
  }

  // Set threads
	if (!threads)
		threads=list_numberOfProcessors();


  // Test date
	if (now==-1 || date<19000000000000LL || date>30000000000000LL)
		error("date is incorrect, use -until YYYY-MM-DD HH:MM:SS to set");

  // Adjust negative version
	if (version<0) 
	{
		list_Jidac jidac(*this);
		jidac.version=LIST_DEFAULT_VERSION;
		if (!jidac.list_read_archive())  // not found?
			jidac.list_read_archive(0, list_subpart(archive, 0).c_str());  // try remote index
		version+=list_size(jidac.ver)-1;
	}

  // Suppress output
	if (list_quiet==LIST_MAX_QUIET) 
	{
		list_con=fopen("nul:", "wb");
		if (!list_con) 
			error("console redirect failed");
	}

	// Execute command
	list_print_datetime();
	printf( "zpaqlist " ZPAQLIST_VERSION " compiled " __DATE__"\n");
	if (command=="-list") 
		return mylist();
	else 
	  usage();
  return 0;
}

inline void list_progress(int64_t ts, int64_t td) 
{
	if (td>ts) td=ts;
	if (td>=1000000) 
		printf("%5.2f%%  %s / %s\n", td*100.0/(ts+0.5),migliaia(td),migliaia2(ts));
}

// Read arc (default: archive) up to -date into ht, dt, ver. Return place to
// append. If errors is not NULL then set it to number of errors found.
int64_t list_Jidac::list_read_archive(int *errors, const char* arc) {
  if (errors) *errors=0;
  dcsize=dhsize=0;

  // Open archive or archive.zpaq. If not found then try the index of
  // a multi-part archive.
  if (!arc) arc=archive.c_str();
  list_Archive in;
  if (!in.open(arc, password)) 
  {
      list_printutf8(arc, stderr);
      printf( " not found.\n");
      if (errors) ++*errors;
      return 0;
  }
  ///list_printutf8(arc, list_con);
	list_print_datetime();

	if (all)
		printf(":all");
	else
	{
		if (version==LIST_DEFAULT_VERSION) 
			printf( ":default");
		else 
			printf( ":until %1.0f: ", version+0.0);
	}
  printf("\n");
  
  // Test password
  if (password) {
    char s[4]={0};
    const int nr=in.read(s, 4);
    if (nr>0 && memcmp(s, "7kSt", 4) && (memcmp(s, "zPQ", 3) || s[3]<1))
	{
		list_print_datetime();
      printf( "zpaqlist:password incorrect\n");
	  exit(1);
	}
    in.seek(-nr, SEEK_CUR);
  }

  
  
	list_global_start=GetTickCount();
	
  // Scan archive contents
  string lastfile=arc; // last named file in streaming format
  if (list_size(lastfile)>5)
    lastfile=lastfile.substr(0, list_size(lastfile)-5); // drop .zpaq
  int64_t block_offset=32*(password!=0);  // start of last block of any type
  int64_t data_offset=block_offset;    // start of last block of d fragments
  int64_t segment_offset=block_offset; // start of last segment
  bool found_data=false;   // exit if nothing found
  bool first=true;         // first segment in archive?
  enum {NORMAL, ERR, RECOVER} pass=NORMAL;  // recover ht from data blocks?
  list_StringBuffer os(32832);  // decompressed block
  map<int64_t, double> compressionRatio;  // block offset -> compression ratio

	
  int lastver=0;
  int blocchini=0;
  // Detect archive format and read the filenames, fragment sizes,
  // and hashes. In JIDAC format, these are in the index blocks, allowing
  // data to be skipped. Otherwise the whole archive is scanned to get
  // this information from the segment headers and trailers.
	int64_t total_time=0;
	
  bool done=false;
  while (!done) {
    try {
			if (pakka)
				if (lastver<1)
				{
					list_print_datetime(); 
					printf( "S2\n");
				}
				
      // If there is an error in the h blocks, scan a second time in RECOVER
      // mode to recover the redundant fragment data from the d blocks.
      libzpaq::Decompresser d;
      d.setInput(&in);
      if (d.findBlock())
        found_data=true;
      else if (pass==ERR) {
        segment_offset=block_offset=32*(password!=0);
        in.seek(block_offset, SEEK_SET);
        if (!d.findBlock()) break;
        pass=RECOVER;
        printf( "Attempting to recover fragment tables...\n");
      }
		else
			break;
	
	
	if ((list_size(ver)-1)!=lastver)
	{
		if (pakka)
		{
			if (((list_size(ver)-1)%2))
			{
				int64_t startprintf=list_mtime();
				list_print_datetime();
			
				printf( "V %06d (%08d) ", list_size(ver)-1, list_size(dt));
				list_progress(list_g_dimensione,  block_offset);
				total_time+=list_mtime()-startprintf;
			}
		}
		lastver=list_size(ver)-1;
	}
      // Read the segments in the current block
      list_StringWriter filename, comment;
      int segs=0;
      while (d.findFilename(&filename)) {
        if (filename.s.size()) {
          for (unsigned i=0; i<filename.s.size(); ++i)
            if (filename.s[i]=='\\') filename.s[i]='/';
          lastfile=filename.s.c_str();
        }
        comment.s="";
        d.readComment(&comment);
    ///    if (pass!=NORMAL)

		if (lastver<2)
		{
			if (pakka)
			{
				if (!(blocchini%1000))
				{
					int64_t startprintf=list_mtime();
					list_print_datetime();
					printf( "B %08d\n", blocchini);
					total_time+=list_mtime()-startprintf;
				}
			}
			blocchini++;
		}
		

	   int64_t usize=0;  // read uncompressed size from comment or -1
        int64_t fdate=0;  // read date from filename or -1
        int64_t fattr=0;  // read attributes from comment as wN or uN
        unsigned num=0;   // read fragment ID from filename
        const char* p=comment.s.c_str();
        for (; isdigit(*p); ++p)  // read size
          usize=usize*10+*p-'0';
        if (p==comment.s.c_str()) usize=-1;  // size not found
        for (; *p && fdate<19000000000000LL; ++p)  // read date
          if (isdigit(*p)) fdate=fdate*10+*p-'0';
        if (fdate<19000000000000LL || fdate>=30000000000000LL) fdate=-1;

        // Read the comment attribute wN or uN where N is a number
        int attrchar=0;
        for (; true; ++p) {
          if (*p=='u' || *p=='w') {
            attrchar=*p;
            fattr=0;
          }
          else if (isdigit(*p) && (attrchar=='u' || attrchar=='w'))
            fattr=fattr*10+*p-'0';
          else if (attrchar) {
            fattr=fattr*256+attrchar;
            attrchar=0;
          }
          if (!*p) break;
        }

        // Test for JIDAC format. Filename is jDC<fdate>[cdhi]<num>
        // and comment ends with " jDC\x01"
        if (comment.s.size()>=4
            && usize>=0
            && comment.s.substr(comment.s.size()-4)=="jDC\x01"
            && filename.s.size()==28
            && filename.s.substr(0, 3)=="jDC"
            && strchr("cdhi", filename.s[17])) {

          // Read the date and number in the filename
          num=0;
          fdate=0;
          for (unsigned i=3; i<17 && isdigit(filename.s[i]); ++i)
            fdate=fdate*10+filename.s[i]-'0';
          for (unsigned i=18; i<filename.s.size() && isdigit(filename.s[i]);
               ++i)
            num=num*10+filename.s[i]-'0';

          // Decompress the block. In recovery mode, only decompress
          // data blocks containing missing list_HT data.
          os.reset();
          os.setLimit(usize);
          d.setOutput(&os);
          libzpaq::SHA1 sha1;
          d.setSHA1(&sha1);
          if (pass!=RECOVER || (filename.s[17]=='d' && num>0 &&
              num<ht.size() && ht[num].csize==LIST_HT_BAD)) {
            d.decompress();
            char sha1result[21]={0};
            d.readSegmentEnd(sha1result);
            if (usize!=int64_t(sha1.usize())) {
              printf( "%s size should be %1.0f, is %1.0f\n",
                      filename.s.c_str(), double(usize),
                      double(sha1.usize()));
              error("incorrect block size");
            }
            if (sha1result[0] && memcmp(sha1result+1, sha1.result(), 20)) {
              printf( "%s checksum error\n", filename.s.c_str());
              error("bad checksum");
            }
          }
          else
            d.readSegmentEnd();

          // Transaction header (type c).
          // If in the future then stop here, else read 8 byte data size
          // from input and jump over it.
          if (filename.s[17]=='c' && fdate>=19000000000000LL
              && fdate<30000000000000LL && pass!=RECOVER) {
            data_offset=in.tell()+1;
            bool isbreak=version<19000000000000LL ? list_size(ver)>version :
                         version<fdate;
            int64_t jmp=0;
            if (!isbreak && os.size()==8) {  // jump
              const char* s=os.c_str();
              jmp=list_btol(s);
              if (jmp<0) {
                printf( "Incomplete transaction ignored\n");
                isbreak=true;
              }
              else if (jmp>0) {
                dcsize+=jmp;
                in.seek(jmp, SEEK_CUR);
              }
            }
            if (os.size()!=8) {
              printf( "Bad JIDAC header size: %d\n", list_size(os));
              isbreak=true;
              if (*errors) ++*errors;
            }
            if (isbreak) {
              done=true;
              break;
            }
            ver.push_back(list_VER());
            ver.back().firstFragment=list_size(ht);
            ver.back().offset=block_offset;
            ver.back().date=fdate;
            ver.back().csize=jmp;
          }

          // Fragment table (type h).
          // Contents is bsize[4] (sha1[20] usize[4])... for fragment N...
          // where bsize is the compressed block size.
          // Store in ht[].{sha1,usize}. Set ht[].csize to block offset
          // assuming N in ascending order.
          else if (filename.s[17]=='h' && num>0 && os.size()>=4
                   && pass!=RECOVER) {
            const char* s=os.c_str();
            const unsigned bsize=list_btoi(s);
            dhsize+=bsize;

            const unsigned n=(os.size()-4)/24;
            if (ht.size()>num) {
              printf(
                "Unordered fragment tables: expected >= %d found %1.0f\n",
                list_size(ht), double(num));
              pass=ERR;
            }
            double usum=0;  // total uncompressed size
            for (unsigned i=0; i<n; ++i) {
              while (ht.size()<=num+i) ht.push_back(list_HT());
              memcpy(ht[num+i].sha1, s, 20);
              s+=20;
              if (ht[num+i].csize!=LIST_HT_BAD) error("duplicate fragment ID");
              usum+=ht[num+i].usize=list_btoi(s);
              ht[num+i].csize=i?-int(i):data_offset;
            }
            if (usum>0) compressionRatio[data_offset]=bsize/usum;
            data_offset+=bsize;
          }

          // Index (type i)
          // Contents is: 0[8] filename 0 (deletion)
          // or:       date[8] filename 0 na[4] attr[na] ni[4] ptr[ni][4]
          // Read into list_DT
          else if (filename.s[17]=='i' && pass!=RECOVER) {
            const bool islist=command=="-list";
            const char* s=os.c_str();
            const char* const end=s+os.size();
            while (s<=end-9) {
              const char* fp=s+8;  // filename
              list_DT& dtr=dt[fp];
              dtr.dtv.push_back(list_DTV());
              list_DTV& dtv=dtr.dtv.back();
              dtv.version=list_size(ver)-1;
              dtv.date=list_btol(s);

              if (dtv.date) ++ver.back().updates;
              else ++ver.back().deletes;
              s+=strlen(fp)+1;  // skip filename
              if (dtv.date && s<=end-8) {
                const unsigned na=list_btoi(s);
                for (unsigned i=0; i<na && s<end; ++i, ++s)  // read attr
                  if (i<8) dtv.attr+=int64_t(*s&255)<<(i*8);
                if (s<=end-4) {
                  const unsigned ni=list_btoi(s);
                  dtv.ptr.resize(ni);
                  for (unsigned i=0; i<ni && s<=end-4; ++i) {  // read ptr
                    const unsigned j=dtv.ptr[i]=list_btoi(s);
                    if (j<1 || j>=ht.size()+(1<<24))
                      error("bad fragment ID");
                    while (j>=ht.size()) {
                      pass=ERR;
                      ht.push_back(list_HT());
                    }
                    dtv.size+=ht[j].usize;
                    ver.back().usize+=ht[j].usize;

                    // Estimate compressed size
                    if (islist) {
                      unsigned k=j;
                      if (ht[j].csize<0 && ht[j].csize!=LIST_HT_BAD)
                        k+=ht[j].csize;
                      if (k>0 && k<ht.size() && ht[k].csize!=LIST_HT_BAD
                          && ht[k].csize>=0)
                        dtv.csize+=compressionRatio[ht[k].csize]*ht[j].usize;
                    }
                  }
                }
              }
            }
          }

          // Recover fragment sizes and hashes from data block
          else if (pass==RECOVER && filename.s[17]=='d' && num>0
                   && num<ht.size()) {
            if (os.size()>=8 && ht[num].csize==LIST_HT_BAD) {
              const char* p=os.c_str()+os.size()-8;
              unsigned n=list_btoi(p);  // first fragment == num or 0
              if (n==0) n=num;
              unsigned f=list_btoi(p);  // number of fragments
              if (n!=num)
                printf( "fragments %u-%u were moved to %u-%u\n",
                    n, n+f-1, num, num+f-1);
              n=num;
              if (f && f*4+8<=os.size()) {
                printf( "Recovering fragments %u-%u at %1.0f\n",
                       n, n+f-1, double(block_offset));
                while (ht.size()<=n+f) ht.push_back(list_HT());
                p=os.c_str()+os.size()-8-4*f;

                // read fragment sizes into ht[n..n+f-1].usize
                unsigned sum=0;
                for (unsigned i=0; i<f; ++i) {
                  sum+=ht[n+i].usize=list_btoi(p);
                  ht[n+i].csize=i ? -int(i) : block_offset;
                }

                // Compute hashes
                if (sum+f*4+8==os.size()) {
                  printf( "Computing hashes for %d bytes\n", sum);
                  libzpaq::SHA1 sha1;
                  p=os.c_str();
                  for (unsigned i=0; i<f; ++i) {
                    for (int j=0; j<ht[n+i].usize; ++j) {

                      sha1.put(*p++);
                    }
                    memcpy(ht[n+i].sha1, sha1.result(), 20);
                  }

                }
              }
            }

            // Correct bad offsets

            if (ht[num].csize!=block_offset) {
              printf( "Changing block %d offset from %1.0f to %1.0f\n",
                     num, double(ht[num].csize), double(block_offset));
              ht[num].csize=block_offset;
            }
          }

          // Bad JIDAC block
          else if (pass!=RECOVER) {
            printf( "Bad JIDAC block ignored: %s %s\n",
                    filename.s.c_str(), comment.s.c_str());
            if (errors) ++*errors;
          }
        }

        // Streaming format
        else if (pass!=RECOVER) {

          // If previous version does not exist, start a new one
          if (list_size(ver)==1) {
            if (list_size(ver)>version) {
              done=true;
              break;
            }
            ver.push_back(list_VER());
            ver.back().firstFragment=list_size(ht);
            ver.back().offset=block_offset;
            ver.back().csize=-1;
          }

          char sha1result[21]={0};
          d.readSegmentEnd(sha1result);
          list_DT& dtr=dt[lastfile];
          if (filename.s.size()>0 || first) {
            dtr.dtv.push_back(list_DTV());
            dtr.dtv.back().date=fdate;
            dtr.dtv.back().attr=fattr;
            dtr.dtv.back().version=list_size(ver)-1;
            ++ver.back().updates;
          }

          dtr.dtv.back().ptr.push_back(list_size(ht));
          if (usize>=0 && dtr.dtv.back().size>=0) dtr.dtv.back().size+=usize;
          else dtr.dtv.back().size=-1;
          dtr.dtv.back().csize+=in.tell()-segment_offset;
          if (usize>=0) ver.back().usize+=usize;
          ht.push_back(list_HT(sha1result+1, usize>0x7fffffff ? -1 : usize,
                          segs ? -segs : block_offset));

        }
        ++segs;
        filename.s="";
        first=false;
        segment_offset=in.tell();
      }  // end while findFilename
      if (!done) segment_offset=block_offset=in.tell();
    }  // end try
    catch (std::exception& e) {
      block_offset=in.tell();
      printf( "Skipping block at %1.0f: %s\n", double(block_offset),
              e.what());
      if (errors) ++*errors;
    }
  }  // end while !done
  if (in.tell()>32*(password!=0) && !found_data)
  {
	list_print_datetime();
 printf("archive contains no data\n");
  }
  in.close();

  // Recompute file sizes in recover mode
  if (pass==RECOVER) {
    printf( "Recomputing file sizes\n");
    for (list_DTMap::iterator p=dt.begin(); p!=dt.end(); ++p) {
      for (unsigned i=0; i<p->second.dtv.size(); ++i) {
        p->second.dtv[i].size=0;
        for (unsigned j=0; j<p->second.dtv[i].ptr.size(); ++j) {
          unsigned k=p->second.dtv[i].ptr[j];
          if (k>0 && k<ht.size())
            p->second.dtv[i].size+=ht[k].usize;
        }
      }
    }
  }
  
  
	fprintf(list_outputlog, "!%d\n", list_size(ver)-1); 
	list_print_datetime();
	printf( "OUTPUT...V %d, F %d, %s bytes %d blocks Otime %1.3f s\n", 
    list_size(ver)-1, list_size(dt), migliaia(block_offset),blocchini,(total_time/1000.0));
 	
  return block_offset;
}


/////////////////////////////// mylist //////////////////////////////////
// List contents
int list_Jidac::mylist() 
{
	int64_t csize=0;
	list_outputlog=stdout;
	
	if (archive=="")
			exit(1);
		
	if (fileoutput!="")
		list_outputlog=fopen(fileoutput.c_str(),"w");
	if (list_outputlog==NULL)
	{
		printf("Error output log is null\n");
		exit(1);
	}
	csize=list_read_archive();
	if (csize==0) 
		exit(1);
	
	vector<list_DTMap::const_iterator> filelist;
	for (list_DTMap::iterator p=dt.begin(); p!=dt.end(); ++p)
	{
		if (p->second.dtv.size()<1) 
		{
			printf( "Invalid index entry: %s\n", p->first.c_str());
			error("corrupted index");
		}
		if (!strstr(p->first.c_str(), ":$DATA")) //fuck off windows metadata
		filelist.push_back(p);
	}
	
/// versions
	for (int i=0; i<list_size(ver); ++i) 
		if (!(i==0 && ver[i].updates==0 && ver[i].deletes==0 && ver[i].date==0 && ver[i].usize==0))
			fprintf(list_outputlog, "| %6d %s\n", i,list_dateToString(ver[i].date).c_str());
	  
	string lastfile="?";

	unsigned int dieci=1;
	unsigned int righe=0;
	for (unsigned fi=0; fi<filelist.size(); ++fi) 
	{	
		list_DTMap::const_iterator p=filelist[fi];
		for (unsigned i=0; i<p->second.dtv.size(); ++i) 
			if (p->second.dtv[i].version>=1 //since
			&& (all || (i+1==p->second.dtv.size() && p->second.dtv[i].date))) 
			if (!strstr(p->first.c_str(), ":$DATA"))
				righe+=4;
	
	}
	/// I need line numbers at the head, not at the tail, of the output
	fprintf(list_outputlog, "+%d\n",righe);
	
	unsigned int blocco = (filelist.size() / 10)+1;
	int64_t startoutput=list_mtime();
	for (unsigned fi=0; fi<filelist.size(); ++fi) 
	{	

		if ((fi+1) % blocco==0)
		{
			list_print_datetime();
			printf("W %03d%% %08d/%.08d\n",(dieci++)*10,fi+1,(int)filelist.size());
		}
		list_DTMap::const_iterator p=filelist[fi];
		for (unsigned i=0; i<p->second.dtv.size(); ++i) 
		{
			if (p->second.dtv[i].version>=1 //since
			&& (all || (i+1==p->second.dtv.size() && p->second.dtv[i].date))) 
			{
					fprintf(list_outputlog, "-%d\n", p->second.dtv[i].version);
					if (p->second.dtv[i].date) 
						fprintf(list_outputlog, "%s\n%s\n",
							list_mydateToString(p->second.dtv[i].date).c_str(),
							migliaia(p->second.dtv[i].size));
					else 
						fprintf(list_outputlog, "D\n0\n");
				
					if (distinct)
						list_printutf8(p->first.c_str(), list_outputlog);
					else
					{
						if (lastfile!=p->first.c_str())
						{
							list_printutf8(p->first.c_str(), list_outputlog);
							lastfile=p->first.c_str();
						}
						else
							fprintf(list_outputlog,"?");
					}
					fprintf(list_outputlog, "\n");
			}
		}
	}


	if (fileoutput!="")
	{
		fseeko(list_outputlog, 0, SEEK_END);
		uint64_t outsize=ftello(list_outputlog);
		list_print_datetime();
		printf("Output %s bytes / %s lines in %1.3f s\n",migliaia(outsize),migliaia2(righe),(list_mtime()-startoutput)/1000.0);
		fclose (list_outputlog);
	}
	return 0;
}



/////////////////////////////// main //////////////////////////////////

// Convert argv to UTF-8 and replace \ with /
int main() 
{
  int argc=0;
  LPWSTR* argw=CommandLineToArgvW(GetCommandLine(), &argc);
  vector<string> args(argc);
  libzpaq::Array<const char*> argp(argc);
  for (int i=0; i<argc; ++i) 
  {
    args[i]=list_wtou(argw[i]);
    argp[i]=args[i].c_str();
  }
  const char** argv=&argp[0];

  list_global_start=list_mtime();  // get start time
  int errorcode=0;
  try 
  {
	list_Jidac jidac;
	errorcode=jidac.doCommand(argc, argv);
  }
  catch (std::exception& e) 
  {
    printf( "zpaqlist exiting from main: %s\n", e.what());
    errorcode=1;
  }
  list_print_datetime();
  printf( "T=%1.3fs", (list_mtime()-list_global_start)/1000.0);
  
  if (errorcode) 
	  printf( " (with errors)\n");
  else 
	printf( " (all OK)\n");
  return errorcode;
}
