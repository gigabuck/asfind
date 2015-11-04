import fnmatch
import os
import re

rootPath = '/tmp/swfDecompile'
pattern = '*.as'

checks_rx = (
    ('[Ss]ecurity\.allowDomain\(.+?\)', 'Permissive Cross-Domain Permissions'),
    ('TextArea\.htmlText\(.+?\)', 'Function Displays HTML Code'),
    ('.{1,15}RemoteObject.{1,15}', 'Function Makes Network Call'),
    ('.{1,15}AMFChannel.{1,15}', 'Function Makes Network Call'),
    ('FileReference\.download\(.+?\)', 'Function Makes Network Call'),
    ('FileReference\.upload\(.+?\)', 'Function Makes Network Call'),
    ('Loader\.load\(.+?\)', 'Function Makes Network Call'),
    ('LocalConnection\.connect\(.+?\)', 'Function Makes Network Call'),
    ('NetConnection\.connect\(.+?\)', 'Function Makes Network Call'),
    ('NetStream\.play\(.+?\)', 'Function Makes Network Call'),
    ('Security\.loadPolicyFile\(.+?\)', 'Function Makes Network Call'),
    ('SharedObject\.getLocal\(.+?\)', 'Function Makes Network Call'),
    ('SharedObject\.getRemote\(.+?\)', 'Function Makes Network Call'),
    ('Socket\.connect\(.+?\)', 'Function Makes Network Call'),
    ('Sound\.load\(.+?\)', 'Function Makes Network Call'),
    ('URLLoader\.load\(.+?\)', 'Function Makes Network Call'),
    ('URLStream\.load\(.+?\)', 'Function Makes Network Call'),
    ('XMLSocket\.connect\(.+?\)', 'Function Makes Network Call'),
    ('ExternalInterface\.call\(.+?\)', 'Function Makes Network Call'),
    ('navigateToURL\(.+?\)', 'Function Makes Network Call'),
    ('sendToURL\(.+?\)', 'Function Makes Network Call'),
    ('URLRequest\(.+?\)', 'Function Accepts URLs'),
    ('NetConnection\.connect\(.+?\)', 'Function Accepts URLs'),
    ('XMLSocket\(.+?\)', 'Function Accepts URLs'),
    ('XMLSocket\.connect\(.+?\)', 'Function Accepts URLs'),
    ('NetStream\.play\(.+?\)', 'Function Accepts URLs'),
    ('TextFormat\.url\(.+?\)', 'Function Accepts URLs'),
    ('FLVPlayback\.load\(.+?\)', 'Function Accepts URLs'),
    ('FLVPlayback\.play\(.+?\)', 'Function Accepts URLs'),
    ('FLVPlayback\.source\(.+?\)', 'Function Accepts URLs'),
    ('FLVPlayback\.skin\(.+?\)', 'Function Accepts URLs'),
    ('FLVPlaybackCaptioning\.source\(.+?\)', 'Function Accepts URLs'),
    ('ImageCell\.source\(.+?\)', 'Function Accepts URLs'),
    ('Loader\.load\(.+?\)', 'Function Performs Content Loading'),
    ('Sound\.load\(.+?\)', 'Function Performs Content Loading'),
    ('Netstream\.play\(.+?\)', 'Function Performs Content Loading'),
    ('ExternalInterface\.call\(.+?\)', 'Function Communicates With Web Browser'),
    ('ExternalInterface\.addCallBack\(.+?\)', 'Function Communicates With Web Browser'),
    ('fscommand\(.+?\)', 'Function Communicates With Web Browser'),
    ('navigateToURL\(.+?\)', 'Function Communicates With Web Browser'),
    ('LoaderInfo\.parameters\(.+?\)', 'Function Accesses FlashVars'),
    ('paramObj\(.+?\)', 'Function Accesses FlashVars'),
    ('SharedObject\.getLocal\(.+?\)', 'Function Accesses SharedObjects'),
    ('SharedObject\.getRemote\(.+?\)', 'Function Accesses SharedObjects'),
    ('Document\.Write\(.+?\)', 'Javascript Function'),
    ('eval\(.+?\)', 'Javascript Function'),
    ('Document\.Cookie\(.+?\)', 'Javascript Function'),
    ('Window\.Location\(.+?\)', 'Javascript Function'),
    ('Document\.URL\(.+?\)', 'Javascript Function'),
    ('Window\.createRequest\(.+?\)', 'Javascript Function'),
    ('.{1,15}paramObj.{1,15}', 'Interesting Keyword'),
	('.{1,15}_root.{1,15}', 'Interesting Keyword'),
    ('.{1,15}_global.{1,15}', 'Interesting Keyword'),
    ('.{1,15}_level0.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Hack.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Kludge.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Bypass.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Steal.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Stolen.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Divert.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Broken.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Trick.{1,15}', 'Interesting Keyword'),
    ('.{1,15}FIXME.{1,15}', 'Interesting Keyword'),
    ('.{1,15}ToDo.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Passw(?:or)?d.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Backdoor.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Debug.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Access\s?Control.{1,15}', 'Interesting Keyword'),
    ('.{1,15}Credential.{1,15}', 'Interesting Keyword'),
    ('.{1,15}XSS.{1,15}', 'Interesting Keyword'),
    ('.{1,15}SQL\s?Injection.{1,15}', 'Interesting Keyword'),
    ('.{1,15}(?:(?:http://.+?/.+?\.\w{1,4})|(?:/\w+?/)).{1,15}', 'Absolute/Relative URL'),
    ('.{1,15}(?:\s|=)(?:service|send|remote)\.\w+\(.+?\)', 'Flex Remoting Method Found'),
	('<endpoint\suri=".+?"/>', 'Flex Remoting Endpoint Found'),
	('<destination\sid=".+?">', 'Flex Remoting Service Found'),
    )

def check_file(rp, fp):
    f = open(fp, 'r')
    content = f.read()
    f.close()
    for rx, rx_desc in checks_rx:
        regex = re.compile(rx, re.IGNORECASE)
        for m in regex.finditer(content):
            start = m.start()
            lineno = content.count('\n', 0, start) + 1
            word = m.group(0)
            print('%s|%s|%s|%s' % (rx_desc, rp, lineno, word.lstrip()))

if __name__ == '__main__':
    for root, dirs, files in os.walk(rootPath):
        for filename in fnmatch.filter(files, pattern):
            fpath = os.path.join(root, filename)
            rpath = os.path.relpath(fpath,rootPath)
            check_file(rpath, fpath)
