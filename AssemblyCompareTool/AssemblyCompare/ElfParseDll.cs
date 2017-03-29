using System;
using System.Runtime.InteropServices;
using System.IO;

namespace AssemblyCompare
{
  public  class ElfParseDll
    { 

        [DllImport("ElfParser.dll", EntryPoint = "ParseElf", CharSet = CharSet.Auto)]
        public static extern int ParseElf(ref byte prtStr); 

        public static void ReplaceElfValue(byte[] fileAbytes)
        {
            var temp = new byte[fileAbytes.Length];
            Array.Copy(fileAbytes, temp, fileAbytes.Length); 
            ElfParseDll.ParseElf(ref fileAbytes[0]);
        } 
    }
}
