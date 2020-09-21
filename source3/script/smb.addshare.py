#!/usr/local/bin/python3
import os
import argparse
from middlewared.client import Client

def make_it_so(args):
    parent_dir = None
    args.pathName
    if not os.path.exists(args.pathName):
        """
        This is experimental and doesn't get called yet.
        Samba bails out early if the path doesn't exist.
        I can probably modify samba to allow this in this case.
        """
        parent_dir = os.path.dirname(args.pathName)
        bn = os.path.basename(args.pathName)
        if not os.path.exists(parent_dir):
            return 1
        pds = Client().call('pool.dataset.query', [('mountpoint', '=', parent_dir)])['id']
        Client.call('pool.dataset.create', {
            'name': f'{pds}/{bn}',
            'share_type': 'SMB',
            'atime': 'OFF',
        })

    Client().call('sharing.smb.create', {
        'path': args.pathName,
        'name': args.shareName,
        'comment': args.comment,
    })

    return 0

def main():
    parser = argparse.ArgumentParser(description='Add SMB Share')
    parser.add_argument('configFile', type=str, help='Config File Path.')
    parser.add_argument('shareName', type=str, help='the name of the share.')
    parser.add_argument('pathName', type=str, help='path to an existing directory.')
    parser.add_argument('comment', type=str, help='comment string to associate with the new share.')
    parser.add_argument('maxConnections', type=str, help='Number of maximum connections to this share.')
    args = parser.parse_args()
    ret = make_it_so(args)


if __name__ == '__main__':
    main()
