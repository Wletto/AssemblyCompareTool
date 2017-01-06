using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace AssemblyCompare
{
  public  class ElfParseDll
    {
        int curcnt = 0;

        [DllImport("ElfParser.dll", EntryPoint = "ParseElf", CharSet = CharSet.Auto)]
        public static extern int ParseElf(ref byte prtStr);


        public static void ReplaceElfValue(byte[] fileAbytes)
        {
            byte[] temp = new byte[fileAbytes.Length];
            Array.Copy(fileAbytes, temp, fileAbytes.Length);

            ElfParseDll.ParseElf(ref fileAbytes[0]);
        }


       public void dump(byte[] filebyte)
        {
            string filename = curcnt.ToString() + ".so";
            BinaryWriter bw;
            try
            {
                bw = new BinaryWriter(new FileStream(filename, FileMode.Create));
                bw.Write(filebyte);
                bw.Close();
                curcnt += 1;
            }
            catch (Exception ex)
            {
                throw new Exception("读取SO文件数据失败，错误信息:" + ex.Message);
            }
        }


        Int32 GetDWORD(byte[] bytes, int offset)
        {
            return ((bytes[offset + 3] << 24) | (bytes[offset + 2] << 16) | (bytes[offset + 1] << 8) | bytes[offset]);
        }
    }
}
