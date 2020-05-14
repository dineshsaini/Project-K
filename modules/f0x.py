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
                'Specify target site.', dest='site')

        self.getParser().add_argument('-q', '--query', help = \
                'Dork to use. If specified, other files will not be read.', \
                dest='query')
        
        self.getParser().add_argument('-i', '--inclusive', help = \
                'This works with `query` option only, if used, will \
                also read dorks from file. ', dest='inc', action="store_true")

        self.getParser().add_argument('-A', '--args', help = \
                'Specify extra query to supply with each dorks.', \
                dest='ex_query')

        self.getParser().add_argument('-C', '--category', help = \
                'Use dorks from this category only.', dest='category')

        self.getParser().add_argument('-S', '--severity', help = \
                'Specify minimum severity(inclusive) dork file to read, \
                range is [0, 10], defalut: 5.', dest='severity', type=int, \
                choices=range(1, 11))

        self.getParser().add_argument( '--only', help = \
                'Use along with severity, to select only a particular value.',\
                dest='s_only', action='store_true')

        self.getParser().add_argument( '--upper', help ='Use along with \
                severity, to mark provided value as upper limit (exclusive).',\
                dest='s_upper', action='store_true')

        self.getParser().add_argument('-a', '--all', help = \
                'Use all the dork files to fetch result (overrides --only, \
                --upper flags).', dest='s_all', action='store_true')

        self.getParser().add_argument('-Q', '--quality', help = \
                'Use only top severity(>=8) dork files (overrides --only, \
                --upper flags). ', dest='s_qual', action='store_true')


        self.getParser().add_argument('-r', '--results', help = \
                'Total results to fetch in one request, default is 30.', \
                dest='page_size', type=int)

        self.getParser().add_argument('-t', '--total', help = \
                'Total results to fetch for each dork, default is 150.', \
                dest='dork_size', type=int)

        self.getParser().add_argument('-T', '--max', help = \
                'Maximum results to fetch for all the dorks combined.', \
                dest='max_results', type=int)

        self.getParser().add_argument('-m', '--mintime', help = \
                'Specify minimum sec to wait between requests, If not \
                specified, default 5 sec range is assumed', dest='min', \
                type=int)

        self.getParser().add_argument('-M', '--maxtime', help = \
                'Specify maximum sec to wait between requests, if not \
                specified, default 5 sec range is assumed.', dest='max', \
                type=int)

        self.getParser().add_argument('-d', '--delay', help = \
                'Specify fix delay(in sec), if specified, took priority \
                over variable delay.', dest='delay', type=int)

        self.getParser().add_argument('-o', '--output', help = \
                'Specify output directory', dest='output')

        self.getParser().add_argument('-j', '--json', help = \
                'Save output in JSON format only', dest='json', \
                action="store_true")

        self.getParser().add_argument('-R', '--report', help = \
                'Create Report along with JSON format ouput, default', \
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

    def main(self):
        self.banner()


if __name__ == "__main__":
    kwargs = {
            'conf': cman
        }
    mod_obj = example(**kwargs)
    mod_obj.call(" ".join(sys.argv[1:]))
