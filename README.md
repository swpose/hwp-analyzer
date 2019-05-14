# hwp-analyzer

It can check the basic information of the hwp file and detect malicious shellcode with yara.
&nbsp;

hwp-analyzer can aid in the following:
- Analyze file structure about FileHeader, BodyText, Bindata, etc.
- Check malicious script inside section with yara.
- Stream List
- File Header Information
- Timestamp
- HWP Summary Information
- BinData Informaion (Save the Decompress data)
- Detect Malicious Shellcode
&nbsp;

### File Information
![문서정보_1](https://user-images.githubusercontent.com/41017200/57670279-89512f00-7649-11e9-9074-8a5cfcf5e41e.png)

### Stream List
![문서정보_2](https://user-images.githubusercontent.com/41017200/57670284-8bb38900-7649-11e9-9f57-9eb7f3e94d26.png)

### Decompress information
![문서정보_3](https://user-images.githubusercontent.com/41017200/57670285-8d7d4c80-7649-11e9-88a5-9e2707fb443e.png)


### Example Sample Hash
- DE9FCCC2AD15037220F82EDB1554A1FA
&nbsp;

### Result Example

    [+] FileHeader Information
    [*] Total Length : 256
      - File Signature : HWP Document File
      - File Version : 5.0.3.4
      - Attribution : 0x00000010
      - Reserved Length: 216
    
    [+] HWP Summary Information
    [*] Blank data is NULL
       - Title : 안녕하십니까
       - Subject :
       - Author : USER
       - Keyword :
       - Comments :
       - Last Saved by : User1
       - Revision Number : 8, 5, 8, 1600 WIN32LEWindows_Unknown_Version
       - Create Time/Date : 2016-04-03 11:58:43.062000
       - Last saved Time/Date : 2018-11-07 07:51:11.519000
    
    [+] Stream List
       -  HwpSummaryInformation
       -  BinData/BIN0001.eps
       -  BinData/BIN0002.gif
       -  BodyText/Section0
       -  DocInfo
       -  DocOptions/_LinkDoc
       -  FileHeader
       -  PrvImage
       -  PrvText
       -  Scripts/DefaultJScript
       -  Scripts/JScriptVersion
    
    [+] BinData Information
       - File Name : BinData/BIN0001.eps
       - File Size : 410639
       - Hex data ~50bytes(pre-Decompress) : b"\xecVKs\xdb6\x10\xbe\xe7W\xa0\x9eqG\xee42\x00\xe2\xc5C\x0f$\x08\x9e\x9a\xc4SO'3\x1d^\xf4\x80-\xb5\xb2\xa8Rt\xecD\xe3\xff\xde\xc5\x83&)"
       - Hex data ~50bytes(Decompress) : b'%!PS-Adobe-3.0 EPSF-3.0\n\n/popmenuw{ exch dup 3 pop'

       - File Name : BinData/BIN0002.gif
       - File Size : 22173
       - Hex data ~50bytes(pre-Decompress) : b'\x94\x97\xf9#\xd3\x0f\x03\x80?\x9b\x9d\xce\xe5\x8a\x19\r#"\xe6\xc8\xd5\xe56\xb7RaQs\x94\xa3\x9cMf\xc4&\xc7\xe6\xa8\xb9j(Q\x8e\xb9G\xee\xa4\x89\n\x15'
       - Hex data ~50bytes(Decompress) : b'GIF89aO\x02\x1b\x03\xc4\x10\x00\xbe\x80\x8d\xdf\xc0\xc6\x9d@S\xf7\xf0\xf2\x84\x10(\xce\xa0\xaa\xad`p\x950E\xe7\xd0\xd5\x8c 7\xef\xe0\xe3\xc6\x90\x9b\xa5'
    
    [+] Detect Malicious Shellcode
       - File name : BIN0001.eps
       - Match rule : [detect_xor]
    
    [*] Timestamp
    +----------------------------+---------------------+---------------------+
    | Stream/Storage name        | Modification Time   | Creation Time       |
    +----------------------------+---------------------+---------------------+
    | Root                       | 2018-11-07 07:51:11 | None                |
    | '\x05HwpSummaryInformation | None                | None                |
    | '                          |                     |                     |
    | 'BinData'                  | 2018-11-07 07:51:11 | 2018-11-07 07:51:11 |
    | 'BinData/BIN0001.eps'      | None                | None                |
    | 'BinData/BIN0002.gif'      | None                | None                |
    | 'BodyText'                 | 2018-11-07 07:51:11 | 2018-11-07 07:51:11 |
    | 'BodyText/Section0'        | None                | None                |
    | 'DocInfo'                  | None                | None                |
    | 'DocOptions'               | 2018-11-07 07:51:11 | 2018-11-07 07:51:11 |
    | 'DocOptions/_LinkDoc'      | None                | None                |
    | 'FileHeader'               | None                | None                |
    | 'PrvImage'                 | None                | None                |
    | 'PrvText'                  | None                | None                |
    | 'Scripts'                  | 2018-11-07 07:51:11 | 2018-11-07 07:51:11 |
    | 'Scripts/DefaultJScript'   | None                | None                |
    | 'Scripts/JScriptVersion'   | None                | None                |
    +----------------------------+---------------------+---------------------+        
&nbsp;


## References
- oletimes, https://github.com/decalage2/oletools/wiki/oletimes
