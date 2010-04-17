#include "buffer.h"
#include "readwrite.h"
#include "exit.h"

char bspace[256];
buffer b = BUFFER_INIT(write,1,bspace,sizeof bspace);

void say(char *s)
{
  if (buffer_puts(&b,s) == -1) _exit(111);
}

main(int argc,char **argv)
{
  char *name;
  char *value;
  unsigned char ch;
  char octal[4];

  name = argv[1];
  if (!name) _exit(100);
  value = argv[2];
  if (!value) _exit(100);

  say("char ");
  say(name);
  say("[] = \"\\\n");

  while (ch = *value++) {
    say("\\");
    octal[3] = 0;
    octal[2] = '0' + (ch & 7); ch >>= 3;
    octal[1] = '0' + (ch & 7); ch >>= 3;
    octal[0] = '0' + (ch & 7);
    say(octal);
  }

  say("\\\n\";\n");
  if (buffer_flush(&b) == -1) _exit(111);
  _exit(0);
}
