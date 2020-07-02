if __name__ == "__main__":
    import sys
    import os

    proj_path = os.path.realpath("{}/../".format(os.path.dirname(os.path\
            .realpath(__file__))))
    sys.path.insert(0, proj_path)

    from lib.config import ConfigManager
    cman = ConfigManager.load("{}/config/default.conf".format(proj_path))
    cman.set('project_path', proj_path)

from lib.modules import BaseModule
import argparse

class f0x(BaseModule):
    """
    f0x: Smart Dork Scanner, Scan dorks as per Severity or Catagory, build
    report in json and html format.

    JSON is used to harvest sensitive urls.
    HTML tells high level view of which level of information is leaked.
    
    Original Project: https://github.com/em-corp/f0x
    """
    __KEYWORDS__ = ['dorks scanner', 'ghdb', 'smart dork sanner', \
            'google hacking database', 'google query', 'search', \
            'dork report', 'url harvester', 'osint', 'osint framework', \
            'scanning']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def defineArgs(self):
        self.getParser().add_argument('-s', '--site', help = \
                'Specify target site.', dest = 'site', metavar = 'target')

        self.getParser().add_argument('-q', '--query', help = \
                'Use this dork, instead of reading from repo files.', \
                dest = 'query', metavar = 'dork')
        
        self.getParser().add_argument('-i', '--inclusive', help = 'Read from \
                repo files for dorks, along with the dork supplied via \
                \'query\' argument. Required \'query\' argument to be \
                present.', dest='inc', action="store_true")

        self.getParser().add_argument('-A', '--args', help = \
                'Specify extra query to supply with each dorks.', \
                dest='ex_query', metavar='query')

        self.getParser().add_argument('-C', '--category', help = \
                'Use dorks from this category only.', dest='category', \
                metavar='cat')

        self.getParser().add_argument('-S', '--severity', help = \
                'Specify minimum severity(inclusive) dork file to read, \
                range is [0, 10]. (defalut: 5)', dest='severity', type=int, \
                choices=range(1, 11), metavar='N', nargs='?', default=5)

        self.getParser().add_argument( '--only', help = 'Use supplied \
                severity as fixed value. Required \'severity\' argument to be \
                present.', dest='s_only', action='store_true')

        self.getParser().add_argument( '--upper', help ='Mark provided \
                severity value as upper limit (exclusive). Required \
                \'severity\' argument to be present.', dest='s_upper', \
                action='store_true')

        self.getParser().add_argument('--all', help = 'Use all the dork \
                available to fetch result. Beware, this will creates so \
                much noise. Note: This flag is not respected when present \
                along with \'severity\'/\'quality\' argument', dest='s_all', \
                action='store_true')

        self.getParser().add_argument('-Q', '--quality', help = \
                'Use only top severity(>=8) dork files to fetch results.\
                This flag overrides others flags/arguments \
                (\'severity\'/\'all\') if present.', dest='s_qual', \
                action='store_true')

        self.getParser().add_argument('-r', '--results', help = \
                'Total results to fetch in one request. (default: 30)', \
                dest='page_size', type=int, metavar='N', default=30)

        self.getParser().add_argument('-t', '--total', help = \
                'Total results to fetch for each dork. (default: 150)', \
                dest='dork_size', type=int, metavar='N', default=150)

        self.getParser().add_argument('-T', '--max', help = \
                'Maximum results to fetch for all the dorks combined.', \
                dest='max_results', type=int, metavar='N')

        self.getParser().add_argument('-m', '--mintime', help = \
                'Specify minimum sec to wait between requests, If not \
                specified, default 5 sec range is assumed', dest='min', \
                type=int, metavar='N')

        self.getParser().add_argument('-M', '--maxtime', help = \
                'Specify maximum sec to wait between requests, if not \
                specified, default 5 sec range is assumed.', dest='max', \
                type=int, metavar='N')

        self.getParser().add_argument('-d', '--delay', help = \
                'Specify fix delay(in sec), if specified, took priority \
                over variable delay.', dest='delay', type=int, metavar='N')

        self.getParser().add_argument('-o', '--output', help = \
                'Specify output directory', dest='output', metavar='dir', \
                required=True)

        self.getParser().add_argument('-j', '--json', help = \
                'Save output in JSON format only', dest='json', \
                action="store_true")

        self.getParser().add_argument('-R', '--report', help = \
                'Create Report along with JSON format ouput. (default)', \
                dest='report', action="store_true")

        self.getParser().add_argument('--update', help = \
                'Update Dorks Repo, and exit', dest='updaterepo', \
                action="store_true")

        self.getParser().add_argument('-L', '--list', help = \
                'List Repo categories, total dorks and exit', dest='listrepo',\
                action="store_true")

    def banner(self):
        print ('''
 .o88o.   .o             o.   
 888 `"  .8'             `8.  
o888oo  .8'  oooo    ooo  `8. 
 888    88    `88b..8P'    88 
 888    88      Y888'      88 
 888    `8.   .o8"'88b    .8' 
o888o    `8. o88'   888o .8'  
        ''');

#-------------------------------------------------------------------------------------------------------------
    #read config file
    def get_value(key):
        with open(getFileName(os.path.dirname(os.path.realpath(__file__)), 'f0x.config'), 'r') as config:
            for line in config:
                if line.startswith(key):
                    return line.split('=')[1].strip('\n')
    
    def getNewDir(o, dn=''):
        out_dir = o
        if out_dir.endswith('/'):
            out_dir += dn 
        else:
            out_dir += '/' + dn
    
        if not os.path.exists(out_dir):
            try:
                os.makedirs(out_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        return out_dir
    
    def getDir(o, dn = ''):
        return getNewDir(o, dn)
    
    def query_encode(query):
        return urlparse.quote_plus(query)
    
    # query, site, extra_query_string
    def createURL(q, s, eqs):
        u = 'https://www.google.com/search?gbv=1&q='
        if q == '':
            print ("Query cannot be empty")
            return
        u += query_encode(q)
        if eqs != '':
            u += '+' + query_encode(eqs)
        if s != '':
            u += '+' + query_encode(s)
        u += '&btnG=Google+Search'
        return u
    
    def getSeverities():
        sev = []
        if severity_flag == 0:
            sev = list (range (severity, 11))
        elif severity_flag  == 1:
            sev = [severity]
        elif severity_flag  == 2:
            sev = list (range (1, severity)) #if severity = 1, return empty set
        return sev
    
    def getFiles(f):
        l = []
        for j in os.listdir(f):
            t = f
            if t.endswith('/'):
                t += j
            else:
                t += '/' + j
    
            if os.path.isfile(t):
                l +=  [t]
            else:
                l += getFiles(t)
        return l
    
    def getDirs(f):
        l = []
        for j in os.listdir(f):
            t = f
            if t.endswith('/'):
                t += j
            else:
                t += '/' + j
    
            if os.path.isdir(t):
                l +=  [t]
                l += getDirs(t)
        return l
    
    def getDorks(rq, inc, svr, cat):
        dorks = []
        if rq:
            if svr == 10:
                dorks += [rq]
            if not inc:
                return dorks
        
        dpath = get_value('dork_path')
        chome = ''
    
        if cat != '':
            chome = re.sub('\.', '/', cat)
       
        dpath = getDir(dpath, chome)
    
        for i in getFiles(dpath):
            with open (i, 'r') as dfile:
                d = ''
                j = ''
                for l in dfile:
                    if l.lstrip().lower().startswith('dork:'):
                        d = re.sub('^[dD][oO][rR][kK]:', '', l.lstrip())
                        d = d.strip()
                    elif l.lstrip().lower().startswith('severity:'):
                        j = re.sub('^severity:', '', l.lstrip().lower())
                        j = j.strip()
                
                if int(j) == svr:
                    dorks.append(d)
    
        return dorks
    
    def getUserAgents():
        uaf = get_value('useragents')
        if not uaf.startswith('/'): #relative path
            uaf = getFileName(os.path.dirname(os.path.realpath(__file__)), uaf)
    
        useragents = []
        with open(uaf, 'r') as uas:
            useragents = [ua.strip('\n') for ua in uas]
        return useragents
    
    
    def wget(u):
        hdrs = {
                'Host': 'www.google.com',
                'User-Agent': random.choice(useragents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Referer': 'https://www.google.com/',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0, no-cache',
                'Pragma': 'no-cache',
                'TE': 'Trailers'
                }
        req = requests.get(u, headers=hdrs)
        return req.text
    
    def getNewRandomDir(o, dn=''):
        return getNewDir(getNewDir(o, dn), str(time.time_ns()))
    
    def getFileName(o, n):
        if o.endswith('/'):
            return o + n
        else:
            return o + '/' + n
    
    def persist(r, d, s, o, fc):
        if fc == 0:
            fd = open(getFileName(o, 'dork.info'), 'w')
            fd.write("dork: {}\n".format(d))
            fd.write("severity: {}\n".format(s))
            fd.close()
        fd = open(getFileName(o, 'dork_' + str(fc + 1)), 'w')
        fd.write(r)
        fd.close()
    
    def getDelay():
        return delay + (random.random() * var_delay)
    
    def pageHasMoreResults(r):
        o = re.search('aria-label="Next page"[^>]*>((Next &gt;)|(<span [^>]*>&gt;</span>))</a>', r, re.I)
        if o:
            return True
        else:
            return False 
    
    mr_achived = 0
    def canFetchMore():
        return (max_results - mr_achived) > 0
    
    # TODO: make it synchronised later
    def updateResultsCount(c):
        global mr_achived
        mr_achived += c
    
    # TODO: make it async later
    def extractURLs(o, res):
        fd = open(getFileName(o, 'urls.txt'), 'a')
    
        for pat in re.findall('\s+href="/url\?q=([^"&]*)[^"]*"[^>]*>', res, re.M|re.I):
            if not re.search('^http(s)?://(www\.)?[^.]*\.google\.com', pat, re.I):
                u = urlparse.unquote(pat)
                fd.write("{}\n".format(u))
    
        fd.close()
    
    def processDork(d, s, qe, ps, ds, o, sev):
        if not canFetchMore():
            return
    
        u = createURL(d, s, qe)
        i = -1
        rFlag = True
        dd = getNewRandomDir(o, 'dorks')
        r = 0
        print("[*] Processing dork: {}".format(d))
        while rFlag and canFetchMore() and ((ps * (i + 1)) <= ds):
            url = ''
            i += 1
            if i == 0:
                url = "{}&start=&num={}".format(u, ps)
            else:
                url = "{}&start={}&num={}".format(u, ps * i, ps)
            t = getDelay()
            print("[*] Sleeping for {} sec.".format(t))
            time.sleep(t)
            print("[*] Processing now.")
            print("[*] Next Page Request: {}".format(r + 1))
            response = wget(url)
            print("[*] Got Response.")
            persist(response, d, sev, dd, r)
            r += 1
            updateResultsCount(ps)
            rFlag = pageHasMoreResults(response)
            extractURLs(dd, response)
    
    # TODO: implement thread
    def dbBuilder():
        for s in getSeverities():    
            for i in getDorks(r_query, inclusive, s, category):
                processDork(i, site, query_extra, page_size, dork_size, out_dir, s)
        print("[*] Finished fetching results.")
    
    def jsonBuilder(o):
        for f in os.listdir(o):
            i = getFileName(o, f)
    
            if os.path.isdir(i):
                if os.path.isfile(getFileName(i, 'urls.txt')):
                    l = []
                    s = ''
                    d = ''
    
                    with open(getFileName(i, 'urls.txt'), 'r') as urls:
                        for u in urls:
                            l += [u.strip('\n')]
                    
                    with open(getFileName(i, 'dork.info'), 'r') as infos:
                        for line in infos:
                            if line.startswith('dork: '):
                                d = re.sub('dork: ', '', line)
                                d = d.strip('\n')
                            elif line.startswith('severity: '):
                                s = re.sub('severity: ', '', line)
                                s = s.strip('\n')
    
                    fd = open(getFileName(i, 'result.json'), 'w')
                    
                    data = {
                            'severity' : s,
                            'dork' : d,
                            'urls' : l
                            }
    
                    fd.write(json.dumps(data))
                    fd.close()
    
    def buildReportObj(dd):
        data = []
        
        for i in range(1, 11):
            data += [{
                    'severity': i,
                    'lists': []
                }]
    
        for d in os.listdir(dd):
            f = getFileName(dd, d)
            
            if os.path.isdir(f):
                if os.path.isfile(getFileName(f, 'result.json')):
                    jd = {}
                    
                    with open(getFileName(f, 'result.json'), 'r') as jfile:
                        jd = json.load(jfile)
                    
                    data[int(jd['severity']) - 1]['lists'] += [{
                            'dork': jd['dork'],
                            'path': './dorks/' + d + '/result.json',
                            'count': len(jd['urls'])
                        }]
        return data
    
    def reportBuilder(o, d):
        of = getFileName(o, 'report.html')
        fd = open(of, 'w')
        banner = '''<div class="banner"><pre>
    .o88o.   .o             o.
     888 `"  .8'             `8.
    o888oo  .8'  oooo    ooo  `8.
     888    88    `88b..8P'    88
     888    88      Y888'      88
     888    `8.   .o8"'88b    .8'
    o888o    `8. o88'   888o .8'
    </pre></div>
    <span class="banner-footer">Report Generated by `<b>f0x</b>`</span>
    '''
    
        do = buildReportObj(getDir(o, d))
        
        css= '''
        .banner{
            font-weight: 600;
        }
        
        .banner-footer {
            font-style: italic;
        }
        
        .severity {
            font-size: 2.4em;
        }
        
        .label {
            font-size: 1.4em;
        }
        
        .label-value {
            font-style: italic;
            font-weight: 600;
        }
    
        '''
    
        fd.write("<html><head><title>OSINT Report - [GHDB]</title><style>{}</style></head><body>".format(css))
        fd.write(banner)
    
        for i in do:
            fd.write('<div><p><span class="severity severity-{}">Severity {}</span></p>'.format(i['severity'], i['severity']))
            for j in i['lists']:
                fd.write('<p><span class="label dorkLabel">Dork Used: </span> <span class="label-value dork">{}</span></p>'.format(j['dork']))
                fd.write('<p><span class="label resultCountLabel">URLs Retrived: </span><span class="label-value resultCount">{}</span></p>'.format(j['count']))
                fd.write('<p><span class="label resultLocLabel">JSON File: </span><span class="label-value resultLoc"><a href="{}">{}</a></span></p>'.format(j['path'], j['path']))
                fd.write('<hr/>')
            fd.write("</div>")
    
        fd.write("</body></html>")
        fd.close()
    
    def getDorkRepoUrl():
        return get_value('repo_url')
    
    
    def mergedir(s, d):
        for i in os.listdir(s):
            if os.path.isfile(getFileName(s, i)):
                shutil.move(getFileName(s,i), getFileName(d, i))
            else:
                mergedir(getDir(s, i), getDir(d, i))
    
    def pullDorksRepo():
        print("[*] Building Dork Repo")
        print("[*] Fetching from '{}'".format(getDorkRepoUrl()))
    
        tmpdir = '/tmp/f0x/'
        if os.path.exists(tmpdir):
            try:
                shutil.rmtree(tmpdir)
            except:
                tmpdir = getNewRandomDir(tmpdir)
        
        Repo.clone_from(getDorkRepoUrl(), tmpdir)
        
        print("[*] Fetching done.".format(getDorkRepoUrl()))
    
        g = getDir(tmpdir, '.git')
        if os.path.exists(g):
            try:
                shutil.rmtree(g)
            except:
                pass
    
        r = getFileName(tmpdir, 'README.md')
        if os.path.isfile(r):
            os.remove(r)
    
        l = getFileName(tmpdir, 'LICENSE')
        if os.path.isfile(l):
            os.remove(l)
        
        mergedir(tmpdir, getDir(get_value('dork_path')))
    
        print("[*] Dork Repo Updated, dork location: {}".format(get_value('dork_path')))
    
    def buildConfFile(cpath):
        r = ''
        d = ''
        u = ''
        try:
            r = get_value('repo_url')
        except:
            pass
    
        try:
            d = get_value('dork_path')
        except:
            pass
    
        try:
            u = get_value('useragents')
        except:
            pass
    
        fd = open(cpath, 'w')
        if r == '':
            fd.write('repo_url={}\n'.format('https://github.com/em-corp/dorks.git'))
        else:
            fd.write('repo_url={}\n'.format(r))
        if d == '':
            fd.write('dork_path={}\n'.format(getDir(os.path.expanduser('~'), '.f0x/dorks')))
        else:
            fd.write('dork_path={}\n'.format(d))
        if u == '':
            fd.write('useragents=./user-agents\n')
        else:
            fd.write('useragents={}\n'.format(u))
        fd.close()
    
    def configure():
        cpath = getFileName(os.path.dirname(os.path.realpath(__file__)), 'f0x.config')
        
        if not os.path.isfile(cpath):
            print ("[*] Creating Configuration file.")
            buildConfFile(cpath)
            print('[*] Done.')
    
        if get_value('repo_url') == '' or \
                get_value('dork_path') == '' or \
                get_value('useragents') == '':
                    print("[*] Error Reading Conf file.")
                    print("[*] Creating new Configuration file.")
                    buildConfFile(cpath)
                    print('[*] Done.')

#-------------------------------------------------------------------------------------------------------------
    def listStats():
        dp = ''
        try:
            dp = self.getConfig().get('dork_path')  #FIXME: add dork_path in conf
        except:
            pass
        if dp == '':
            print("[ERROR]: No Dorks Available. Check Config file.")
            return
    
        for i in getDirs(dp):
            dc = re.sub('^{}[/]?'.format(dp), '', i)
            dc = re.sub('/', '.', dc)
            td = len (getFiles(i)) 
            print("[*] Category: {}".format(dc))
            print("[**] Total Dork: {}\n".format(td))

#-------------------------------------------------------------------------------------------------------------
    def main(self):
        self.banner()
        if self.getArg('listrepo'):
            self.listStats()
            return
         


if __name__ == "__main__":
    kwargs = {
            'conf': cman
        }
    mod_obj = example(**kwargs)
    mod_obj.call(" ".join(sys.argv[1:]))
