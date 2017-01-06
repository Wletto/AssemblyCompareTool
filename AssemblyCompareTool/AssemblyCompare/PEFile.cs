using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AssemblyCompare
{
    public class PEFile
    { 
        /// <summary>
        /// 清洗PE文件数据
        /// </summary>
        /// <param name="fileAbytes"></param>
        public static void ReplacePEValue(byte[] fileAbytes)
        {
            try
            {
                // 读取 61-64 字节，获取PE头长度 
                int pelens =ReadByte(fileAbytes, 60, 4); 
                // 读取PE 9-12位  这里是时间戳 替换为00 00 00 00
                fileAbytes[pelens + 8] = 0;
                fileAbytes[pelens + 9] = 0;
                fileAbytes[pelens + 10] = 0;
                fileAbytes[pelens + 11] = 0;
                //读取 PE 21-22 得出  IMAGE_OPTION_HEADER32 长度 
                int imageoptionheaderindex = ReadByte(fileAbytes, pelens+20, 2);

                // 读取PE 45-48 得到 BASEOFCODE  2000 ,这里从字节里面读出来的是00002000
                int codenum = ReadByte(fileAbytes, pelens+44, 4);   
                // 读取 PE 85-88 得到SIZEOFHEADERS 200 
                int sizenum = ReadByte(fileAbytes, pelens+84, 4);  // modify liuwei 0628 这里计算出来的 2000有误，不能将16进制转换为10进制

                            //// 读取PE 53-56 得到 IMAGE_BASE 10000000
                            //var imagebase = TenToSixteen(fileAbytes[pelens + 55]) + TenToSixteen(fileAbytes[pelens + 54]) + TenToSixteen(fileAbytes[pelens + 53]) + TenToSixteen(fileAbytes[pelens + 52]);
                            //int imagenum = Convert.ToInt32(imagebase);

                int BaseIndex = codenum - sizenum; //1800
                //int BaseIndex = 1800;
                // 读出PE 169-172 字节  得出 DEBUG_DIR目录 
                int debug_offset = ReadByte(fileAbytes, pelens+168, 4);
                if (debug_offset != 0)
                {
                    int debugdirindex = debug_offset - BaseIndex;
                    // 先转换为10进制 再计算
                    // int tempindex = Convert.ToInt32(DEBUG_DIRSTR) - BaseIndex;

                    // debug directory RVA .text  段 
                    // int debugdirindex = Convert.ToInt32(tempindex.ToString(), 16);

                    // DEBUGDIR 往后  48 字节 ,这里抹掉PDBID 和时间戳。
                    // 读出PE 173-176 字节得出 DEBUG_DIR 长度
                    // var DEBUG_DIRPath = TenToSixteen(fileAbytes[pelens + 175]) + TenToSixteen(fileAbytes[pelens + 174]) + TenToSixteen(fileAbytes[pelens + 173]) + TenToSixteen(fileAbytes[pelens + 172]);
                    // int debugdirLens = Convert.ToInt32(DEBUG_DIRPath, 16);
                   
                    // 找到DEBUG目录开始地址，替换指定长度为0, 这里是抹掉PDBID，时间戳
                    // int debugdir_lens = ReadByte(fileAbytes, pelens + 172, 4);
                    //????这里直接用52不合适，应该取其长度
                    for (int i = 0; i < 52; i++)
                    {
                        fileAbytes[debugdirindex + i] = 0;
                    }
                }

                //meta的长度和偏移都为可能为0，需要判断长度
                // metadata  目录起始位置为 169 + 64 =233  ~236 
                // metadata 目录位置  Meta_DIRSTR     // 经验值 00002008 十进制是 8200，这里的169 ????
                //var meta_data = ReadByte(fileAbytes, pelens + 232, 4);
               int  meta_data = 8200;
                if (meta_data == 0) return;
                // 先转换为10进制 再计算
                meta_data = meta_data - BaseIndex; 

                meta_data = meta_data + 8; // meta_data RVA 地址 
                int size0 =ReadByte(fileAbytes, meta_data, 4);
                var dotnetindex = size0 - BaseIndex; 

                // 定位到MVID ,这里是.NET 数据流的起始位置  
                dotnetindex = dotnetindex + 32;

                /// 直接读size     #~  ，#strings, #US,  #GUID
                /// #~ sizeindex      dotnetindex=dotnetindex+4
                dotnetindex = dotnetindex + 4; 
                int size1 = ReadByte(fileAbytes, dotnetindex, 4);
                // #strings
                dotnetindex = dotnetindex + 12; 
                int size2 = ReadByte(fileAbytes, dotnetindex, 4); 
                // #US
                dotnetindex = dotnetindex + 20; 
                int size3 = ReadByte(fileAbytes, dotnetindex, 4); 

                int size = size1 + size2 + size3;

                /// .net 数据流的目录结构长度为40 ,这里为啥是40，需要获取长度。????
                var netDataDir = dotnetindex + 40;
                netDataDir = netDataDir + size;

                /// 往后替换16个字节 
                for (int i = 0; i < 16; i++)
                {
                    fileAbytes[netDataDir + i] = 0;
                }
                
                // mvid 检索并替换
                var mvidindx = MVIDIndex(fileAbytes);
                if (mvidindx > 0)
                {
                    // 这里是过滤出 <PrivateImplementationDetails> 的位置，然后往后38个长度的字节抹零处理。加上本身60个长度
                    for (int i = 0; i < 98; i++)
                    {
                        fileAbytes[mvidindx + i] = 0;
                    }
                }

                
            }
            catch (Exception e)
            {
                System.Console.Out.WriteLine(e.ToString());
            }
        }

      

        /// <summary>
        /// 10 进制转 16进制
        /// </summary>
        /// <param name="two"></param>
        /// <returns></returns>
        public static string TenToSixteen(int two)
        {
            var temp = string.Format("{0:x}", two);
            if (temp.Length < 2)
            {
                temp = temp.PadLeft(2, '0');
            }
            return temp;
        }


        /// <summary>
        /// 读取字节数据
        /// </summary>
        /// <param name="filebytes"></param>
        /// <param name="startindex"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        public static int ReadByte(byte[] filebytes, int startindex, int len)
        {
            StringBuilder sb = new StringBuilder();
            int index = startindex + len - 1;
            for (int i = index; i >= startindex; i--)
            {
                sb.Append(TenToSixteen(filebytes[i]));
            }
            var temp = sb.ToString();
            if(temp.Length>0)
            {
                //将十六进制“10”转换为十进制
                int lens=Convert.ToInt32(temp, 16);
                return lens; 
            }
            else
            {
                return 0;
            } 
        }

        public static int MVIDIndex(byte[] inputbytes)
        {
                                          
            //16进制  {3C, 50, 72, 69, 76, 61, 74, 65, 49, 6D, 70, 6C, 65, 6D, 65, 6E ,74, 61 ,74, 69 ,6F, 6E ,44, 65, 74, 61, 69, 6C, 73 ,3E};
            byte[] aa = new byte[] { 60, 80, 114, 105, 118, 97, 101, 73, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 68, 101, 116, 97, 105, 108, 115, 62 };
            
            // int query = inputbytes.Select((x, i) => new { i, x = inputbytes.Skip(i).Take(30) }).FirstOrDefault(x => x.x.SequenceEqual(aa)).i;

            var contents = BitConverter.ToString(inputbytes);
            contents=contents.Replace("-","");
            var keystr = "3C50726976617465496D706C656D656E746174696F6E44657461696C733E";            
            var query = contents.IndexOf(keystr);
            query = query / 2;
            return query;
        }
    }
}
