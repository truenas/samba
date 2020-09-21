#!/usr/local/bin/python3

import argparse
from middlewared.client import Client

def del_share(args):
    id = Client().call('sharing.smb.query', [('name', '=', args.shareName)], {'get': True})['id']
    Client().call('sharing.smb.delete', id)

def main():
    parser = argparse.ArgumentParser(description='Delete SMB Share')
    parser.add_argument('configFile', type=str, help='Config File Path.')
    parser.add_argument('shareName', type=str, help='the name of the share.')
    args = parser.parse_args()
    del_share(args)

if __name__ == '__main__':
    main()
