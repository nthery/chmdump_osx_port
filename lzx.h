#include <stdint.h>

#define UBYTE uint8_t
#define UWORD uint16_t
#define ULONG uint32_t
#define BYTE int8_t
#define WORD int16_t
#define LONG int32_t

int LZXinit(int window);
int LZXdecompress(UBYTE *inbuf, UBYTE *outbuf, ULONG inlen, ULONG outlen);
