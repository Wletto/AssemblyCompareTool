using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks; 
using Microsoft.Win32; 
using System.IO; 
using System.Security.Cryptography; 


namespace AssemblyCompare
{
    class Program
    { 

        Program() 
        {
            
        }

        static int Main(string[] args)
        {

            if (args.Length != 3)
            {
                System.Console.Out.WriteLine(" <比较目录> <基准目录> <差量存放目录>");
                return -1;
            } 

            FileCompare instance = new FileCompare();

           // return instance.CompareFiles(@"I:\Homs3.0\OPlus\trunk\Tools\AssemblyCompareTool\Compare\1", @"I:\Homs3.0\OPlus\trunk\Tools\AssemblyCompareTool\Compare\2", @"I:\Homs3.0\OPlus\trunk\Tools\AssemblyCompareTool\Compare\3");


            if (!System.IO.Directory.Exists(args[0]))
            {
                System.Console.Out.WriteLine("目录 " + args[0] + " 不存在!!!");
                return -2;
            }
            if (!System.IO.Directory.Exists(args[1]))
            {
                System.Console.Out.WriteLine("目录 " + args[1] + " 不存在!!!");
                return -3;
            }
            if (!System.IO.Directory.Exists(args[2]))
            {
                System.Console.Out.WriteLine("目录 " + args[2] + " 不存在,将自动创建");
                System.IO.Directory.CreateDirectory(args[2]);
            }
            return instance.CompareFiles(args[0], args[1], args[2]);
        }  
       
    }
}
