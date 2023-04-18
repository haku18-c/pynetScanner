import nmap3
import argparse
import socket
from prettytable import PrettyTable

class PortScanner:

     def __init__(self,target):
         self.target = target
         self.nmap = nmap3.Nmap()
         self.ip = socket.gethostbyname(self.target)
         self.technique = nmap3.NmapScanTechniques()

     def top_ports_mode(self):
         json = self.nmap.scan_top_ports(self.target)
         ip = json[self.ip]
         # ip information parser
         # result ports info

         print('\n\nDomain Name System\n')
         print('[Type]\t\t[Hostname]\n')
         for host in ip['hostname']:
            print(host['type']+'\t\t'+host['name'])

         ports = ip['ports']
         print('\n\t\t[============= '+self.ip+' =============]\n')
         print('Protocol\tPort\tState\t\tReason\t\tService\n')
         for i in range(len(ports)):
            print(ports[i]['protocol'] + '\t\t' + ports[i]['portid'] + '\t' + ports[i]['state']  , end='')
            tabs = '\t\t'
            if ports[i]['state'] == 'filtered':
                 tabs = '\t'
                 print(tabs + ports[i]['reason'], end='')
            else:
                 tabs = '\t\t'
                 print(tabs + ports[i]['reason'], end='')
            if ((ports[i]['reason'] == 'conn-refused') or  (ports[i]['reason'] == 'no-response')):
                 tabs = '\t'
                 print(tabs + ports[i]['service']['name'])
            else:
                 tabs = '\t\t'
                 print(tabs + ports[i]['service']['name'])

         print('\n' + json['runtime']['summary'] + '!')


     def dns_enum(self):
         json = self.nmap.nmap_dns_brute_script(self.target)
         print('Address\t\tHostname\n')
         for info in json:
             print(info['address'] + '\t' + info['hostname'])


     def os_detect(self):
         # must be root user
         json = self.nmap.nmap_os_detection(self.target)
         ip = json[self.ip]
         # ip information parser
         table = PrettyTable()
         print('\n\n\t\t[===================== Operating System ========================] ')
         table.field_names = ['name', 'type', 'accuracy','line', 'cpe']
         for i in ip['osmatch']:
           table.add_row([i['name'], i['osclass']['type'], i['accuracy'],i['line'],i['cpe']])
         # result ports info
         print(table)

         print('\n\nDomain Name System\n')
         print('[Type]\t\t[Hostname]\n')
         for host in ip['hostname']:
            print(host['type']+'\t\t'+host['name'])

         ports = ip['ports']
         print('\n\t\t[============= '+self.ip+' =============]\n')
         print('Protocol\tPort\tState\t\tReason\t\tService\n')
         for i in range(len(ports)):
            print(ports[i]['protocol'] + '\t\t' + ports[i]['portid'] + '\t' + ports[i]['state']  , end='') 
            tabs = '\t\t'
            if ports[i]['state'] == 'filtered':
                 tabs = '\t'
                 print(tabs + ports[i]['reason'], end='')
            else:
                 tabs = '\t\t'
                 print(tabs + ports[i]['reason'], end='')
            if ((ports[i]['reason'] == 'conn-refused') or  (ports[i]['reason'] == 'no-response')):
                 tabs = '\t'
                 print(tabs + ports[i]['service']['name'])
            else:
                 tabs = '\t\t'
                 print(tabs + ports[i]['service']['name'])

         print('\n' + json['runtime']['summary'] + '!')

     def scan_types(self, params):
         json = None
         if params:
            json = self.nmap.nmap_version_detection(self.target)
         else:
            json = self.technique()
            json = json.nmap_syn_scan(self.target)
         ip = json[self.ip]
         table = PrettyTable()
         table.field_names = ['protocol', 'port', 'name', 'state', 'reason', 'product','version', 'method', 'cpe']
         for x in ip['ports']:
             if x['cpe'] == []:
                 x['cpe'].append({'cpe':'NULL'})
             if 'product' not in x['service'].keys():
                x['service']['product'] = 'NULL'
             if 'version' not in x['service'].keys():
                x['service']['version'] = 'NULL'
         for i in ip['ports']:
             table.add_row([i['protocol'],i['portid'], i['service']['name'],i['state'], i['reason'], i['service']['product'],i['service']['version'], i['service']['method'],i['cpe'][0]['cpe']])
         print(table)

     def subnet_scanner(self, record=True):
         json = self.nmap.nmap_subnet_scan(self.target)
         if record:
            fd = open('record_subnet_scanner.txt', 'a')
            fd.write(json)
         print(json)


if __name__ == '__main__':
     parse = argparse.ArgumentParser(description="Python Nmap Port Scanner")
     parse.add_argument('-t', help='target host', type=str)
     parse.add_argument('-type', help='type of scanning: [tp, od, vd, de, sb]', type=str)
     args = parse.parse_args()

     '''

     type of scanner
     tp = top port scanner
     od = os detection
     vd = version detection
     de = dns enum

     '''

     ps = PortScanner(target=args.t)
     args.type = args.type.lower()
     if args.type == 'tp':
        ps.top_ports_mode()
     elif args.type == 'de':
        ps.dns_enum()
     elif args.type == 'od':
        ps.os_detect()
     elif args.type == 'vd':
        ps.scan_types(True)
     elif args.type == 'ss':
        ps.scan_types(False)
     elif args.type == 'sb':
        ps.subnet_scanner()
     else:
        print('Argument -type not found[!]')
        print('list of arg : ')
        print('tp => Top Ports Scanner ')
        print('od => Operating System Scanner ')
        print('de => DNS Enumeration')
        print('sb => Subnet Scanner ')
        print('ss => Nmap Syn Scanner ')
        print('Example for enumerating dns :')
        print('\tsudo python3 netEnums.py -t target.com -type de  ')
        print('\tsudo python3 netEnums.py -t target.com -type de  ')

