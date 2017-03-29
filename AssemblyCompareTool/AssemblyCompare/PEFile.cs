using System;
using System.Text;

namespace AssemblyCompare
{
    public static class PEFile
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
                var pelens =ReadByte(fileAbytes, 60, 4); 
                // 读取PE 9-12位  这里是时间戳 替换为00 00 00 00
                fileAbytes[pelens + 8] = 0;
                fileAbytes[pelens + 9] = 0;
                fileAbytes[pelens + 10] = 0;
                fileAbytes[pelens + 11] = 0;
                //读取 PE 21-22 得出  IMAGE_OPTION_HEADER32 长度 
                var imageoptionheaderindex = ReadByte(fileAbytes, pelens+20, 2);

                // 读取PE 45-48 得到 BASEOFCODE  2000 ,这里从字节里面读出来的是00002000
                var codenum = ReadByte(fileAbytes, pelens+44, 4);   
                // 读取 PE 85-88 得到SIZEOFHEADERS 200 
                var sizenum = ReadByte(fileAbytes, pelens+84, 4);  // modify liuw 0628 这里计算出来的 2000有误，不能将16进制转换为10进制

                //// 读取PE 53-56 得到 IMAGE_BASE 10000000
                //var imagebase = ReadByte(fileAbytes, pelens+53, 4);
                //int imagenum = Convert.ToInt32(imagebase);

                var BaseIndex = codenum - sizenum; //1800
                //int BaseIndex = 1800;

                //替换校验和，在微软可执行格式中，这个域被忽略并且置为0 。这个规则的一个例外情况是信任服务，这类文件必须有一个合法的校验和
                var checkSum = ReadByte(fileAbytes, pelens + 88, 4);
                if (checkSum != 0)
                {
                    fileAbytes[pelens + 88] = 0;
                    fileAbytes[pelens + 89] = 0;
                    fileAbytes[pelens + 90] = 0;
                    fileAbytes[pelens + 91] = 0;
                }

                // 读出PE 169-172 字节  得出 DEBUG_DIR目录 0x3300
                var debug_offset = ReadByte(fileAbytes, pelens+168, 4);
                if (debug_offset != 0)
                {
                    var debugdirindex = debug_offset - BaseIndex;
                    // 先转换为10进制 再计算
                    // int tempindex = Convert.ToInt32(DEBUG_DIRSTR) - BaseIndex;

                    // debug directory RVA .text  段 
                    // int debugdirindex = Convert.ToInt32(tempindex.ToString(), 16);

                    // DEBUGDIR 往后  48 字节 ,这里抹掉PDBID 和时间戳。
                    // 读出PE 173-176 字节得出 DEBUG_DIR 长度
                    // var DEBUG_DIRPath =  ReadByte(fileAbytes, pelens+173, 4);
                    // int debugdirLens = Convert.ToInt32(DEBUG_DIRPath, 16);
                   
                    // 找到DEBUG目录开始地址，替换指定长度为0, 这里是抹掉PDBID，时间戳
                    // int debugdir_lens = ReadByte(fileAbytes, pelens + 172, 4);
                    //这里直接用52不合适，应该取其长度
                   
                    //pdb路径初始位置
                    var pdbindex = debugdirindex + 52;
                    var contents = BitConverter.ToString(fileAbytes, pdbindex);
                    contents = contents.Replace("-", "");
                    var keystr = "2E706462";  //.pdb 二进制码   
                    var query = contents.IndexOf(keystr);
                    query = query / 2;
                    var pdblen = query + 4;
                    for (var i = 0; i < 52 + pdblen; i++)
                    {
                        fileAbytes[debugdirindex + i] = 0;
                    }
                }

                //meta的长度和偏移都为可能为0，需要判断长度
                // metadata  目录起始位置为 169 + 64 =233  ~236 
                // metadata 目录位置  Meta_DIRSTR     // 经验值 00002008 十进制是 8200，这里的169  
                var meta_data = ReadByte(fileAbytes, pelens + 232, 4);
                //var  meta_data = 8200; 这里是固定值。
                if (meta_data == 0) return;
                // 先转换为10进制 再计算
                meta_data = meta_data - BaseIndex; 

                //替换强名称                
                var StrongNameRVAIndex = meta_data + 32;
                var StrongNameSigtureRVA = ReadByte(fileAbytes, StrongNameRVAIndex, 4);
                var StrongNameSIZEIndex = meta_data + 36;
                var StrongNameSigtureSIZE = ReadByte(fileAbytes, StrongNameSIZEIndex, 4);
                //获取强名称在文件中的位置
                var StrongNameLocation = StrongNameSigtureRVA - BaseIndex;
                if (StrongNameSigtureSIZE != 0)
                {
                    for (var i = 0; i < StrongNameSigtureSIZE; i++)
                    {
                        fileAbytes[StrongNameLocation + i] = 0;
                    }
                }

                meta_data = meta_data + 8; // meta_data RVA 地址 
                var size0 =ReadByte(fileAbytes, meta_data, 4);
                //元数据标头
                var dotnetindex = size0 - BaseIndex;
                //var tmp = dotnetindex ;

                ////获取版本长度
                //var versionlength = ReadByte(fileAbytes, dotnetindex + 12, 4);
                //// 定位到MVID ,这里是.NET 数据流的起始位置  
                //dotnetindex = dotnetindex + versionlength;
                ////定位到#GUID目录，获取其位置及大小
                //dotnetindex = dotnetindex + 44;
                ////位置
                //var OFFset = ReadByte(fileAbytes, dotnetindex, 4);
                //var size = ReadByte(fileAbytes, dotnetindex + 4, 8);
                ////#GUID数据流起始位置
                //var netDataDir = tmp + OFFset;
                //大小

                //获取版本长度
                var versionlength = ReadByte(fileAbytes, dotnetindex + 12, 4);
                // 定位到MVID ,这里是.NET 数据流的起始位置  
                dotnetindex = dotnetindex + versionlength + 20;

                /// 直接读size     #~  ，#strings, #US,  #GUID
                /// #~ sizeindex      dotnetindex=dotnetindex+4
                dotnetindex = dotnetindex + 4; 
                var size1 = ReadByte(fileAbytes, dotnetindex, 4);
                // #strings
                dotnetindex = dotnetindex + 12; 
                var size2 = ReadByte(fileAbytes, dotnetindex, 4); 
                // #US
                dotnetindex = dotnetindex + 20; 
                var size3 = ReadByte(fileAbytes, dotnetindex, 4); 
                var size = size1 + size2 + size3;//#~、#Strings、#US的数据流大小
                /// .net 数据流的目录结构长度为40 = 8(#US大小及名称) + 16（#GUID） + 16(#Blob)
                var netDataDir = dotnetindex + 40;
                netDataDir = netDataDir + size;

                /// 往后替换16个字节,mvid ,即抹去#GUID
                for (var i = 0; i < 16; i++)
                {
                    fileAbytes[netDataDir + i] = 0;
                }
                
                // switch case 超过6个时，会自动优化，生成这个字符串， 检索并替换
                var switchCaseIndex = SwitchCaseStr(fileAbytes);
                if (switchCaseIndex <= 0) return;
                {
                    // 这里是过滤出 <PrivateImplementationDetails> 后面签名的位置（不包括签名前面的"<"符号），然后往后36个长度的字节抹零处理，抹掉该签名
                    for (var i = 0; i < 36; i++)
                    {
                        fileAbytes[switchCaseIndex + i] = 0;
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
        private static string TenToSixteen(int two)
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
        private static int ReadByte(byte[] filebytes, int startindex, int len)
        {
            var sb = new StringBuilder();
            var index = startindex + len - 1;
            for (var i = index; i >= startindex; i--)
            {
                sb.Append(TenToSixteen(filebytes[i]));
            }
            var temp = sb.ToString();
            if(temp.Length>0)
            {
                //将十六进制“10”转换为十进制
                var lens=Convert.ToInt32(temp, 16);
                return lens; 
            }
            else
            {
                return 0;
            } 
        }

        /// <summary>
        /// 当类文件中的swithcase中的case超过6个时，会自动优化
        /// </summary>
        /// <param name="inputbytes"></param>
        /// <returns></returns>
        private static int SwitchCaseStr(byte[] inputbytes)
        {
            //<PrivateImplementationDetails> 是一种机制。在.net中，如果switch中出现6个以上的case，.net编译器就会触发该机制，自动对某些指令进行优化。
                         
            //16进制  {3C, 50, 72, 69, 76, 61, 74, 65, 49, 6D, 70, 6C, 65, 6D, 65, 6E ,74, 61 ,74, 69 ,6F, 6E ,44, 65, 74, 61, 69, 6C, 73 ,3E};
            byte[] aa = new byte[] { 60, 80, 114, 105, 118, 97, 101, 73, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 68, 101, 116, 97, 105, 108, 115, 62 };
            
            // int query = inputbytes.Select((x, i) => new { i, x = inputbytes.Skip(i).Take(30) }).FirstOrDefault(x => x.x.SequenceEqual(aa)).i;
            //将输入的字节类型数组转为16进制字符串
            var contents = BitConverter.ToString(inputbytes);
            contents=contents.Replace("-","");
            var keystr = "3C50726976617465496D706C656D656E746174696F6E44657461696C733E";

            //获取<PrivateImplementationDetails>的位置
            var query = contents.IndexOf(keystr);

            //该位置除以2即为<PrivateImplementationDetails>在PE文件中的索引位置，再加上31，即可到达<PrivateImplementationDetails>后面的签名部分，每次编译签名均不相同，因此该部分必须抹除
            query = query / 2 + 31;
            return query;
        }
    }
}
