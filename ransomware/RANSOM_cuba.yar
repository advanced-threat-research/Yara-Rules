rule cuba_ransomware  {
   
   meta:
   
      description = "Rule to detect Fidel/Cuba Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-01"
      reference = "https://id-ransomware.blogspot.com/2019/12/cuba-ransomware.html"
      hash = "b952e63fe46b25ee4ecb725373bddd1b1776fbc4ba73aee7b7b384a3b0f7f71e"
      hash = "78ce13d09d828fc8b06cf55f8247bac07379d0c8b8c8b1a6996c29163fa4b659"
      
   strings:
       
       //http://phoenixlabs.org
       $s1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 70 00 68 00 6F 00 65 00 6E 00 69 00 78 00 6C 00 61 00 62 00 73 00 2E 00 6F 00 72 00 67 00 }
       
       //Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
       $s2 = { 50 65 72 6D 69 73 73 69 6F 6E 20 69 73 20 67 72 61 6E 74 65 64 20 74 6F 20 61 6E 79 6F 6E 65 20 74 6F 20 75 73 65 20 74 68 69 73 20 73 6F 66 74 77 61 72 65 20 66 6F 72 20 61 6E 79 20 70 75 72 70 6F 73 65 2C 20 69 6E 63 6C 75 64 69 6E 67 20 63 6F 6D 6D 65 72 63 69 61 6C 20 61 70 70 6C 69 63 61 74 69 6F 6E 73 2C 20 61 6E 64 20 74 6F 20 61 6C 74 65 72 20 69 74 20 61 6E 64 20 72 65 64 69 73 74 72 69 62 75 74 65 20 69 74 20 66 72 65 65 6C 79 2C 20 73 75 62 6A 65 63 74 20 74 6F 20 74 68 65 20 66 6F 6C 6C 6F 77 69 6E 67 20 72 65 73 74 72 69 63 74 69 6F 6E 73 3A }
       
       //you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
       $s3 = { 79 6F 75 20 6D 75 73 74 20 6E 6F 74 20 63 6C 61 69 6D 20 74 68 61 74 20 79 6F 75 20 77 72 6F 74 65 20 74 68 65 20 6F 72 69 67 69 6E 61 6C 20 73 6F 66 74 77 61 72 65 2E 20 49 66 20 79 6F 75 20 75 73 65 20 74 68 69 73 20 73 6F 66 74 77 61 72 65 20 69 6E 20 61 20 70 72 6F 64 75 63 74 2C 20 61 6E 20 61 63 6B 6E 6F 77 6C 65 64 67 6D 65 6E 74 20 69 6E 20 74 68 65 20 70 72 6F 64 75 63 74 20 64 6F 63 75 6D 65 6E 74 61 74 69 6F 6E 20 77 6F 75 6C 64 20 62 65 20 61 70 70 72 65 63 69 61 74 65 64 20 62 75 74 20 69 73 20 6E 6F 74 20 72 65 71 75 69 72 65 64 2E }
       
       //2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
       $s4 = { 32 2E 20 41 6C 74 65 72 65 64 20 73 6F 75 72 63 65 20 76 65 72 73 69 6F 6E 73 20 6D 75 73 74 20 62 65 20 70 6C 61 69 6E 6C 79 20 6D 61 72 6B 65 64 20 61 73 20 73 75 63 68 2C 20 61 6E 64 20 6D 75 73 74 20 6E 6F 74 20 62 65 20 6D 69 73 72 65 70 72 65 73 65 6E 74 65 64 20 61 73 20 62 65 69 6E 67 20 74 68 65 20 6F 72 69 67 69 6E 61 6C 20 73 6F 66 74 77 61 72 65 2E }
       
       //ListDrop supports P2P, P2B, and DAT formats compressed with 7-Zip, GZip, or Zip.
       $s5 = { 4C 00 69 00 73 00 74 00 44 00 72 00 6F 00 70 00 20 00 73 00 75 00 70 00 70 00 6F 00 72 00 74 00 73 00 20 00 50 00 32 00 50 00 2C 00 20 00 50 00 32 00 42 00 2C 00 20 00 61 00 6E 00 64 00 20 00 44 00 41 00 54 00 20 00 66 00 6F 00 72 00 6D 00 61 00 74 00 73 00 20 00 63 00 6F 00 6D 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 37 00 2D 00 5A 00 69 00 70 00 2C 00 20 00 47 00 5A 00 69 00 70 00 2C 00 20 00 6F 00 72 00 20 00 5A 00 69 00 70 00 2E 00 }
       
       //Unknown file format.  Check the list and try again.
       $s6 = { 55 00 6E 00 6B 00 6E 00 6F 00 77 00 6E 00 20 00 66 00 69 00 6C 00 65 00 20 00 66 00 6F 00 72 00 6D 00 61 00 74 00 2E 00 20 00 20 00 43 00 68 00 65 00 63 00 6B 00 20 00 74 00 68 00 65 00 20 00 6C 00 69 00 73 00 74 00 20 00 61 00 6E 00 64 00 20 00 74 00 72 00 79 00 20 00 61 00 67 00 61 00 69 00 6E 00 2E 00 }
       
       //Copyright (C) 2005 Cory Nelson
       $s7 = { 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 30 00 35 00 20 00 43 00 6F 00 72 00 79 00 20 00 4E 00 65 00 6C 00 73 00 6F 00 6E 00 }
       
       //Phoenix Labs &Homepage
       $s8 = { 50 00 68 00 6F 00 65 00 6E 00 69 00 78 00 20 00 4C 00 61 00 62 00 73 00 20 00 26 00 48 00 6F 00 6D 00 65 00 70 00 61 00 67 00 65 00 }
       
       //0Drag lists to merge here.
       $s9 = { 30 00 44 00 72 00 61 00 67 00 20 00 6C 00 69 00 73 00 74 00 73 00 20 00 74 00 6F 00 20 00 6D 00 65 00 72 00 67 00 65 00 20 00 68 00 65 00 72 00 65 00 2E 00 }
        
        condition:

           uint16(0) == 0x5a4d and 
           filesize < 2000KB and 
           all of them
}
