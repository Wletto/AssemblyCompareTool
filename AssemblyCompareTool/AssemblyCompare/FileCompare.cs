using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AssemblyCompare
{
    public class FileCompare
    {   

        /// <summary>
        /// 目录文件比较
        /// </summary>
        /// <param name="previousVerDir">上一版本目录</param>
        /// <param name="newVerDir">最新版本目录</param>
        /// <param name="differenceVerDir">差异程序包目录</param>
        /// <returns></returns>
       public  int CompareFiles(string previousVerDir, string newVerDir, string differenceVerDir)
        {
            var fileList1 = ListFiles(previousVerDir, "*", 1); 
            var fileList2 = ListFiles(newVerDir, "*", 1); 

            var diffResult = DiffFileList(fileList1, fileList2);

            var commonList = diffResult[0];
            var insertList = diffResult[1];

            var modifyList = new List<string>();
            foreach (var fileName in commonList)
            {
                if (Directory.Exists(previousVerDir + fileName) || Directory.Exists(newVerDir + fileName)) continue;
                Console.Out.WriteLine("文件对比： " + previousVerDir + fileName + " 和文件 " + newVerDir + fileName);
                if (!FileEqual(previousVerDir + fileName, newVerDir + fileName))
                {
                    modifyList.Add(fileName);
                }
            } 
            foreach (var fileName in insertList)
            {
                if (Directory.Exists(previousVerDir + fileName))
                {
                    Directory.CreateDirectory(differenceVerDir + fileName);
                    Console.Out.WriteLine("目录创建 " + differenceVerDir + fileName);
                }
                else
                {
                    var pathName = differenceVerDir + fileName;
                    var dirName = pathName.Substring(0, pathName.LastIndexOf('\\'));
                    Directory.CreateDirectory(dirName);
                    File.Copy(previousVerDir + fileName, differenceVerDir + fileName, true);
                    Console.Out.WriteLine("复制文件  " + previousVerDir + fileName + " 到 " + differenceVerDir + fileName);
                }
            }

            foreach (var fileName in modifyList)
            {
                var pathName = differenceVerDir + fileName;
                var dirName = pathName.Substring(0, pathName.LastIndexOf('\\'));
                Directory.CreateDirectory(dirName);
                File.Copy(previousVerDir + fileName, differenceVerDir + fileName, true);
                Console.Out.WriteLine("复制文件 " + previousVerDir + fileName + " 到 " + differenceVerDir + fileName);
            }
            Console.ReadLine();
            return 0;
        }

       /// <summary>
       /// 读取文件返回MD5码
       /// </summary>
       /// <param name="fileA"></param>
       /// <param name="fileB"></param>
       private static bool FileEqual(string fileA, string fileB)
       {
           var md5CodeA = "";
           var md5CodeB = "";
           if (File.Exists(fileA))
           {
               var fileAbytes = File2Bytes(fileA);
               if (fileAbytes.Length > 0)
               {
                   if (IsDllFile(fileA))
                   {
                       PEFile.ReplacePEValue(fileAbytes);
                   } 
                   else if (IsSoFile(fileA))
                   {
                       ElfParseDll.ReplaceElfValue(fileAbytes); 
                   } 
                   md5CodeA = GetMD5HashFromFile(fileAbytes);
                   Console.Out.WriteLine("【MD5码】 " + fileA + " = " + md5CodeA);
               }
           }
           else
           {
               Console.Out.WriteLine(" 文件 " + fileA + " 不存在!!!");
               return false;
           }

           if (File.Exists(fileB))
           {
               var fileBbytes = File2Bytes(fileB);
               if (fileBbytes.Length <= 0) return (md5CodeA == md5CodeB);
               if (IsDllFile(fileB))
               {
                   PEFile.ReplacePEValue(fileBbytes);
               } 
               else if (IsSoFile(fileB)) 
               {
                   ElfParseDll.ReplaceElfValue(fileBbytes); 
               } 
               md5CodeB = GetMD5HashFromFile(fileBbytes);
               Console.Out.WriteLine("【MD5码】 " + fileB + " = " + md5CodeB);
           }
           else
           {
               Console.Out.WriteLine(" 文件 " + fileB+ " 不存在!!!");
               return false;
           }
 
           return (md5CodeA == md5CodeB);
       }

        /// <summary>
        /// 查找目录文件列表
        /// </summary>
        /// <param name="path"></param>
        /// <param name="file"></param>
        /// <param name="r"></param>
        /// <returns></returns>
       private static List<string> ListFiles(string path, string file, int r)
       {
           var searchOption = (r == 1) ? (SearchOption.AllDirectories) : (SearchOption.TopDirectoryOnly);
           var filenameList = Directory.EnumerateFileSystemEntries(path, file, searchOption).Select(filename => filename.Substring(path.Length)).ToList();
            //文件名排个序
           filenameList.Sort(string.Compare);
           return filenameList;
       }

        /// <summary>
        /// 不同文件清单
        /// </summary>
        /// <param name="list1"></param>
        /// <param name="list2"></param>
        /// <returns></returns>
       private static List<List<string>> DiffFileList(List<string> list1, List<string> list2)
       {
           list1.Sort(string.Compare);
           list2.Sort(string.Compare);

           var result = new List<List<string>>();
           var insertList = new List<string>();
           var removeList = new List<string>();
           var commonList = new List<string>();

           var index1 = 0;
           var index2 = 0;
           var n1 = list1.Count();
           var n2 = list2.Count();
           while (index1 < n1 && index2 < n2)
           {
               var compareValue = string.Compare(list1[index1], list2[index2]);
               if (compareValue == 0)
               {
                   commonList.Add(list1[index1]);
                   index1++;
                   index2++;
               }
               else if (compareValue < 0)
               {
                   insertList.Add(list1[index1]);
                   index1++;
               }
               else if (compareValue > 0)
               {
                   removeList.Add(list2[index2]);
                   index2++;
               }
           }
           while (index1 < n1)
           {
               insertList.Add(list1[index1]);
               index1++;
           }
           while (index2 < n2)
           {
               removeList.Add(list2[index2]);
               index2++;
           }

           result.Add(commonList);
           result.Add(insertList);
           result.Add(removeList);

           return result;
       }
         
  
        /// <summary>
        /// 判断是否为PE 文件
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
       private static bool IsDllFile(string fileName)
       {
           return fileName.EndsWith(".dll") || fileName.EndsWith(".exe");
       }

        /// <summary>
        /// 判断是否为SO文件
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
       private static bool IsSoFile(string fileName)
       {
           return fileName.EndsWith(".so");
       }

       /// <summary>
       /// 获取文件的MD5码
       /// </summary>
       /// <param name="fileName">传入的文件名（含路径及后缀名）</param>
       /// <returns></returns>
       public string GetMD5HashFromFile(string fileName)
       {
           try
           {
               var file = new FileStream(fileName, System.IO.FileMode.Open);
               MD5 md5 = new MD5CryptoServiceProvider();
               var retVal = md5.ComputeHash(file);
               file.Close();
               var sb = new StringBuilder();
               foreach (var t in retVal)
               {
                   sb.Append(t.ToString("x2"));
               }
               return sb.ToString();
           }
           catch (Exception ex)
           {
               throw new Exception("MD5码生成失败，错误信息:" + ex.Message);
           }
       }

        /// <summary>
        /// 获取文件的MD5码
        /// </summary> 
        /// <param name="filebytes">文件数据字节</param>
        /// <returns></returns>
        private static string GetMD5HashFromFile(byte[] filebytes)
       {
           try
           {
               MD5 md5 = new MD5CryptoServiceProvider();
               var retVal = md5.ComputeHash(filebytes);
               var sb = new StringBuilder();
               foreach (var t in retVal)
               {
                   sb.Append(t.ToString("x2"));
               }
               return sb.ToString();
           }
           catch (Exception ex)
           {
               throw new Exception("MD5 码生成失败，错误信息:" + ex.Message);
           }
       }

       /// <summary>
       /// 将文件转换为byte数组
       /// </summary>
       /// <param name="path">文件地址</param>
       /// <returns>转换后的byte数组</returns>
       private static byte[] File2Bytes(string path)
       {
           if (!File.Exists(path))
           {
               return new byte[0];
           }
           var fi = new FileInfo(path);
           var buff = new byte[fi.Length];
           var fs = fi.OpenRead();
           fs.Read(buff, 0, Convert.ToInt32(fs.Length));
           fs.Close();
           return buff;
       } 
    }
}
