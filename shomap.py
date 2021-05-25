import json
import math
import time
from itertools import count
from shodan import Shodan
import sys
import argparse

print('''
    ,-:` \;',`'-, 
  .'-;_,;  ':-;_,'.
 /;   '/    ,  _`.-\ 
| '`. (`     /` ` \`|
|:.  `\`-.   \_   / |
|     (   `,  .`\ ;'|
 \     | .'     `-'/
  `.   ;/        .'
jgs `'-._____.
''')

my_parser = argparse.ArgumentParser(description='Create visualization out of Shodan query')

my_parser.add_argument("-q", "--query",
                       metavar='query',
                       type=str,
                       help='Shodan query')
my_parser.add_argument("-p", "--pages",
                       metavar='query',
                       type=int,
                       default=28,
                       help='Pages to retrieve')

args = my_parser.parse_args()

api = Shodan('SHODAN_API_KEY')


if not args.query:
    print("Please specify your query")
    print("Run #python3 shomap.py -h for help")
    sys.exit()

def get_shodan():
    more_super_dict = {"nodes": [], 'links':[]}

    asset_id = 0
    query = args.query
    with open("shomap_data1.json", "w+") as f:
        for counter in count(): # ?
            success = 0
            while success == 0:
                try:
                    results = api.search(query,page=counter+1)
                    success = 1
                except Exception as e:
                    time.sleep(5)
                    print('Failed, sleeping for 5 sec...')

                    # print('[!] Problem with Shodan API ' + str(e))

            print("[*] Retrieving page " + str(counter + 1))
            pages = math.ceil(results['total'] / 100)
            if counter == args.pages:  # pages + 1:
                break

            for c,i in enumerate(results['matches']):
                try:
                    super_dict = {'id': asset_id, 'fake': 0, 'asn': i['asn'], 'port': i['port'],
                                  'hostnames': i['hostnames'], 'city': i['location']['city'],
                                  'lat': i['location']['latitude'], 'lon': i['location']['longitude'],
                                  'country': i['location']['country_name'], 'domains': i['domains'], 'title': '',
                                  'common_name': '', 'ip': '', 'organization': '', 'vulns': [], 'org': i['org']}

                    asset_id = asset_id + 1

                    if 'ssl' in i:
                        try:
                            super_dict['common_name'] = i['ssl']['cert']['subject']['CN']
                            super_dict['organization'] = i['ssl']['cert']['subject']['O']
                        except:
                            pass

                    if 'vulns' in i:
                        for vuln in i['vulns']:
                            super_dict['vulns'].append(vuln)

                    if 'http' in i:
                        super_dict['title'] = i['http']['title']

                    super_dict['ip'] = i['ip_str']

                    more_super_dict['nodes'].append(super_dict)
                except:
                    break

        rsult = json.dumps(more_super_dict, indent=4)
        f.write(rsult)
        print("[i] File has been saved as shomap_data1.json")


def prepare_viz(path):
    nodes_set = set()
    help = {}
    categories = ['port', 'org','country','city']
    for category in categories:
        print('[*] Grouping by ' + category)
        with open(path, "r+") as f:
            json_f = json.load(f)

            for i in json_f['nodes']:
                if i['port'] == 0:
                    break
                if i[category] not in help.keys():
                    nodes_set.add(i[category])
                    last_id = json_f['nodes'][-1]['id']
                    help.update({i[category]: last_id + 1})
                    json_f['nodes'].append(
                        {"id": last_id + 1, "fake": 1, "country": i[category], "port": 0, "city": "", "org": ""})
                    json_f['links'].append({"source": i['id'], "target": help[i[category]], "value": 1})

                else:
                    json_f['links'].append({"source": i['id'], "target": help[i[category]], "value": 1})

            f = open("shomap_data_"+category+".json", "w")
            f.write(json.dumps(json_f, indent=4))
            f.close()
    # print()

print("[*] Gathering data from Shodan")
get_shodan()

print("[*] Preparing visualization")
prepare_viz("shomap_data1.json")

## in js file, paths are hardcoded,
## everytime it runs, data will be overwritten
