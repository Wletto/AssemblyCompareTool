using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AssemblyCompare
{
    public class FileCompare
    {   

        /// <summary>
        /// 目录文件比较
        /// </summary>
        /// <param name="dir1"></param>
        /// <param name="dir2"></param>
        /// <param name="dir3"></param>
        /// <returns></returns>
       public  int CompareFiles(string dir1, string dir2, string dir3)
        {
            List<string> file_list1 = ListFiles(dir1, "*", 1); 
            List<string> file_list2 = this.ListFiles(dir2, "*", 1); 

            List<List<string>> diff_result = this.DiffFileList(file_list1, file_list2);

            List<string> common_list = diff_result[0];
            List<string> insert_list = diff_result[1];
            List<string> remove_list = diff_result[2];

            List<string> modify_list = new List<string>();
            foreach (string file_name in common_list)
            {
                if (!System.IO.Directory.Exists(dir1 + file_name) && !System.IO.Directory.Exists(dir2 + file_name))
                {
                    System.Console.Out.WriteLine("文件对比： " + dir1 + file_name + " 和文件 " + dir2 + file_name);
                    if (!FileEqual(dir1 + file_name, dir2 + file_name))
                    {
                         modify_list.Add(file_name);
                    }
                }
            } 
            foreach (string file_name in insert_list)
            {
                if (System.IO.Directory.Exists(dir1 + file_name))
                {
                    System.IO.Directory.CreateDirectory(dir3 + file_name);
                    System.Console.Out.WriteLine("目录创建 " + dir3 + file_name);
                }
                else
                {
                    string path_name = dir3 + file_name;
                    string dir_name = path_name.Substring(0, path_name.LastIndexOf('\\'));
                    System.IO.Directory.CreateDirectory(dir_name);
                    System.IO.File.Copy(dir1 + file_name, dir3 + file_name, true);
                    System.Console.Out.WriteLine("复制文件  " + dir1 + file_name + " 到 " + dir3 + file_name);
                }
            }

            foreach (string file_name in modify_list)
            {
                string path_name = dir3 + file_name;
                string dir_name = path_name.Substring(0, path_name.LastIndexOf('\\'));
                System.IO.Directory.CreateDirectory(dir_name);
                System.IO.File.Copy(dir1 + file_name, dir3 + file_name, true);
                System.Console.Out.WriteLine("复制文件 " + dir1 + file_name + " 到 " + dir3 + file_name);
            }
            Console.ReadLine();
            return 0;
        }

       /// <summary>
       /// 读取文件返回MD5码
       /// </summary>
       /// <param name="fileA"></param>
       /// <param name="fileB"></param>
       private  bool FileEqual(string fileA, string fileB)
       { 
           byte[] fileAbytes;
           byte[] fileBbytes;
           string md5codeA = "";
           string md5codeB = "";

           if (File.Exists(fileA))
           {
               fileAbytes = File2Bytes(fileA);
               if (fileAbytes.Length > 0)
               {
                   if (this.IsDllFile(fileA))
                   {
                       PEFile.ReplacePEValue(fileAbytes);
                   } 
                   else if (this.IsSOFile(fileA))
                   {
                       ElfParseDll.ReplaceElfValue(fileAbytes); 
                   }
                  // System.IO.File.WriteAllBytes(@"I:\Homs3.0\OPlus\trunk\Tools\AssemblyCompareTool\Compare\cache1.dll", fileAbytes);
                   md5codeA = GetMD5HashFromFile(fileAbytes);
                   System.Console.Out.WriteLine("【MD5码】 " + fileA + " = " + md5codeA);
               }
           }
           else
           {
               System.Console.Out.WriteLine(" 文件 " + fileA + " 不存在!!!");
               return false;
           }

           if (File.Exists(fileB))
           {
               fileBbytes = File2Bytes(fileB);
               if (fileBbytes.Length > 0)
               {
                   if (this.IsDllFile(fileB))
                   {
                       PEFile.ReplacePEValue(fileBbytes);
                   } 
                   else if (this.IsSOFile(fileB)) 
                   {
                       ElfParseDll.ReplaceElfValue(fileBbytes); 
                   }
                  // System.IO.File.WriteAllBytes(@"I:\Homs3.0\OPlus\trunk\Tools\AssemblyCompareTool\Compare\cache2.dll", fileBbytes);
                   md5codeB = GetMD5HashFromFile(fileBbytes);
                   System.Console.Out.WriteLine("【MD5码】 " + fileB + " = " + md5codeB);
               }
           }
           else
           {
               System.Console.Out.WriteLine(" 文件 " + fileB+ " 不存在!!!");
               return false;
           }
 
           return (md5codeA == md5codeB);
       }

        /// <summary>
        /// 查找目录文件列表
        /// </summary>
        /// <param name="_path"></param>
        /// <param name="_file"></param>
        /// <param name="_r"></param>
        /// <returns></returns>
       private List<string> ListFiles(string _path, string _file, int _r)
       {
           SearchOption searchOption = (_r == 1) ? (SearchOption.AllDirectories) : (SearchOption.TopDirectoryOnly);
           List<string> filenameList = new List<string>();
           foreach (string filename in Directory.EnumerateFileSystemEntries(_path, _file, searchOption))
           {
               filenameList.Add(filename.Substring(_path.Length));
           }
           //文件名排个序
           filenameList.Sort((a, b) =>
           {
               return string.Compare(a, b);
           });
           return filenameList;
       }

        /// <summary>
        /// 不同文件清单
        /// </summary>
        /// <param name="list1"></param>
        /// <param name="list2"></param>
        /// <returns></returns>
       private List<List<string>> DiffFileList(List<string> list1, List<string> list2)
       {
           list1.Sort((a, b) =>
           {
               return string.Compare(a, b);
           });
           list2.Sort((a, b) =>
           {
               return string.Compare(a, b);
           });

           List<List<string>> result = new List<List<string>>();
           List<string> insert_list = new List<string>();
           List<string> remove_list = new List<string>();
           List<string> common_list = new List<string>();

           int index1 = 0;
           int index2 = 0;
           int n1 = list1.Count();
           int n2 = list2.Count();
           while (index1 < n1 && index2 < n2)
           {
               int compare_value = string.Compare(list1[index1], list2[index2]);
               if (compare_value == 0)
               {
                   common_list.Add(list1[index1]);
                   index1++;
                   index2++;
               }
               else if (compare_value < 0)
               {
                   insert_list.Add(list1[index1]);
                   index1++;
               }
               else if (compare_value > 0)
               {
                   remove_list.Add(list2[index2]);
                   index2++;
               }
           }
           while (index1 < n1)
           {
               insert_list.Add(list1[index1]);
               index1++;
           }
           while (index2 < n2)
           {
               remove_list.Add(list2[index2]);
               index2++;
           }

           result.Add(common_list);
           result.Add(insert_list);
           result.Add(remove_list);

           return result;
       }
         
  
        /// <summary>
        /// 判断是否为PE 文件
        /// </summary>
        /// <param name="file_name"></param>
        /// <returns></returns>
       private bool IsDllFile(string file_name)
       {
           return file_name.EndsWith(".dll") || file_name.EndsWith(".exe");
       }

        /// <summary>
        /// 判断是否为SO文件
        /// </summary>
        /// <param name="file_name"></param>
        /// <returns></returns>
       private bool IsSOFile(string file_name)
       {
           return file_name.EndsWith(".so");
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
               FileStream file = new FileStream(fileName, System.IO.FileMode.Open);
               MD5 md5 = new MD5CryptoServiceProvider();
               byte[] retVal = md5.ComputeHash(file);
               file.Close();
               StringBuilder sb = new StringBuilder();
               for (int i = 0; i < retVal.Length; i++)
               {
                   sb.Append(retVal[i].ToString("x2"));
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
       /// <param name="fileName">传入的文件名（含路径及后缀名）</param>
       /// <returns></returns>
       public string GetMD5HashFromFile(byte[] filebytes)
       {
           try
           {
               MD5 md5 = new MD5CryptoServiceProvider();
               byte[] retVal = md5.ComputeHash(filebytes);
               StringBuilder sb = new StringBuilder();
               for (int i = 0; i < retVal.Length; i++)
               {
                   sb.Append(retVal[i].ToString("x2"));
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
       public static byte[] File2Bytes(string path)
       {
           if (!File.Exists(path))
           {
               return new byte[0];
           }
           FileInfo fi = new FileInfo(path);
           byte[] buff = new byte[fi.Length];
           FileStream fs = fi.OpenRead();
           fs.Read(buff, 0, Convert.ToInt32(fs.Length));
           fs.Close();

           return buff;
       } 
    }
}
