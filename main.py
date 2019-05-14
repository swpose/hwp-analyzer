from binascii import hexlify
from oletools.thirdparty import olefile
from oletools.thirdparty import xglob
from oletools.thirdparty.prettytable import prettytable
import olefile, sys, optparse, os, zlib, yara

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))

_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))

if not _parent_dir in sys.path:
    sys.path.insert(0, _parent_dir)

def stream_list(ole):
    tmp_list = []
    listdir = (ole.listdir())
    print ()
    print ('[+] Stream List')
    for content in listdir:
        if len(content) >= 2:
            print ('  -  %s' %'/'.join(content))
        else:
            print ('  -  %s' %''.join(content))
    return listdir


def fileheader(ole):
    stream = ole.openstream('FileHeader')
    data = stream.read()
    print ()
    print ('[+] FileHeader Information')
    print ('[*] Total Length : %s' %len(data))
    print ('   - File Signature : %s ' %(data[:32]).decode())
    pre_version = (hexlify(data[32:36]).decode()[::-1][::2])
    version = ('.'.join(pre_version))
    print ('   - File Version : %s ' %version)
    print ('   - Attribution : 0x%s' %(hexlify(data[36:40]).decode())[::-1])
    print ('   - Reserved Length: %s' %(len(data)-40))
    

def hwpsummary(ole):
    print ()
    print ('[+] HWP Summary Information')
    print ('[*] Blank data is NULL')
    dic = (ole.getproperties('\005HwpSummaryInformation', convert_time=True))
    print ('   - Title : %s' %dic[2])
    print ('   - Subject : %s' %dic[3])
    print ('   - Author : %s' %dic[4])
    print ('   - Keyword : %s' %dic[5])
    print ('   - Comments : %s' %dic[6])
    print ('   - Last Saved by : %s' %dic[8])
    print ('   - Revision Number : %s' %dic[9])
    print ('   - Create Time/Date : %s' %dic[12])
    print ('   - Last saved Time/Date : %s' %dic[13])


def bin_data(ole,bin_list):
    dic = {}
    print ()
    print ('[+] BinData Information')
    for content in bin_list:
        if content[0] == 'BinData':
            print ('   - File Name : %s' %content[0]+'/'+content[1])
            bin_text = ole.openstream(content[0]+'/'+content[1])
            print ('   - File Size : %s' %ole.get_size(content[0]+'/'+content[1]))
            data2 = bin_text.read()
            print ('   - Hex data ~50bytes(pre-Decompress) : %s' %data2[:50])
            zobj = zlib.decompressobj(-zlib.MAX_WBITS)
            data3 = zobj.decompress(data2)
            print ('   - Hex data ~50bytes(Decompress) : %s' %data3[:50])
            f = open('./'+content[1]+'_Decom.txt','wb')
            f.write(data3)
            f.close
            print ()
            
            dic[content[1]] = (hexlify(data3).decode())

    return dic


def detect_yara(dic):
    print ('[+] Detect Malicious Shellcode')
    rules = yara.compile(filepath = './shellcode_pattern.yar')
    for filename in dic:
        matches = rules.match(filename+'_Decom.txt')
        if matches:
            print ('   - File name : %s' %filename)
            print ('   - Match rule : %s' %matches)


def dt2str(dt):
    if dt is None:
        return None
    dt = dt.replace(microsecond=0)
    return str(dt)


def process_ole(ole):
    t = prettytable.PrettyTable(['Stream/Storage name', 'Modification Time', 'Creation Time'])
    t.align = 'l'
    t.max_width = 26
    t.add_row(('Root', dt2str(ole.root.getmtime()), dt2str(ole.root.getctime())))
    for obj in ole.listdir(streams=True, storages=True):
        t.add_row((repr('/'.join(obj)), dt2str(ole.getmtime(obj)), dt2str(ole.getctime(obj))))
    print(t)


def timestamp():
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-r", action="store_true", dest="recursive",
                      help='find files recursively in subdirectories.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
                      help='if the file is a zip archive, open all files from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-f", "--zipfname", dest='zip_fname', type='str', default='*',
                      help='if the file is a zip archive, file(s) to be opened within the zip. Wildcards * and ? are supported. (default:*)')

    (options, args) = parser.parse_args()

    if len(args) == 0:
        print(__doc__)
        parser.print_help()
        sys.exit()

    for container, filename, data in xglob.iter_files(args, recursive=options.recursive,
                                                      zip_password=options.zip_password, zip_fname=options.zip_fname):
        if container and filename.endswith('/'):
            continue
        full_name = '%s in %s' % (filename, container) if container else filename
        print('')
        if data is not None:
            # data extracted from zip file
            ole = olefile.OleFileIO(data)
        else:
            # normal filename
            ole = olefile.OleFileIO(filename)
        print ('[*] Timestamp')
        process_ole(ole)
        ole.close()


if __name__ == "__main__":
    try:
        stream = []
        var1 = sys.argv[1]
        ole = olefile.OleFileIO(var1)
        fileheader(ole)
        hwpsummary(ole)
        bin_list = stream_list(ole)
        if [s for s in bin_list if "BinData" in s]:
            decom = bin_data(ole, bin_list)
        try:
            detect_yara(decom)
        except Exception:
            print ()
            print ('Error, BinData not exist')
        ole.close()
        timestamp()
        
    except Exception as e:
        print (e)
