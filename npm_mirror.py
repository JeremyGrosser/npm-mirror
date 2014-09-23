#!/usr/bin/env python
from traceback import print_exc
import logging
import argparse
import urllib2
import hashlib
import os.path
import os
import sys
import json


REGISTRY_URL = 'https://registry.npmjs.org'
MIRROR_PATH = '/var/lib/mirror/npm'
MIRROR_URL = 'https://archive.example.com/npm'
PACKAGE_BLACKLIST = ('error: forbidden', 'registry/jDataView')

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S'))
log = logging.getLogger('npm_mirror')
log.addHandler(handler)
log.setLevel(logging.INFO)


def request(url):
    log.debug('GET %s', url)
    req = urllib2.Request(url, headers={
        'User-agent': 'node/0.8.11 linux x64'
    })
    try:
        res = urllib2.urlopen(req, timeout=600)
    except urllib2.HTTPError as e:
        log.error('%i %s', e.code, url)
        res = e.fp
    return res


def get_package_index(force_download=False):
    last_update_path = os.path.join(MIRROR_PATH, 'last_update')
    if not force_download:
        try:
            last_update = open(last_update_path, 'r').read().strip('\r\n\t ')
            if last_update:
                params = '?startkey=%s' % last_update
            else:
                params = ''
        except:
            params = ''
    else:
        params = ''
    res = request('http://registry.npmjs.org/-/all/since%s' % params)
    packages = json.load(res)
    with open(last_update_path, 'w') as fd:
        fd.write(str(packages['_updated']))
    del packages['_updated']
    return packages


def get_package_info(package, download=True):
    if download:
        res = request('http://registry.npmjs.org/%s' % package.encode('utf8'))
        res = json.load(res)
        res['_fullmeta'] = True
        return res
    else:
        with open(os.path.join(MIRROR_PATH, package, 'package.json'), 'r') as fd:
            return json.load(fd)


def check_sha(path, expected_digest):
    sha = hashlib.new('sha1')
    with open(path, 'rb') as fd:
        sha.update(fd.read())
    return (sha.hexdigest() == expected_digest)


def update_package(package, meta):
    if not 'versions' in meta:
        log.error('No versions field in package info for %s', package)
        return None

    package_path = os.path.join(MIRROR_PATH, package.encode('utf8'))
    if not os.path.exists(package_path):
        log.debug('Creating directory %s', package_path)
        os.makedirs(package_path)

    for version, versioninfo in meta['versions'].items():
        disturl = versioninfo['dist']['tarball']
        digest = versioninfo['dist']['shasum']
        tarname = disturl.rsplit('/', 1)[1]
        tarpath = os.path.join(package_path, tarname)
        meta['versions'][version]['dist']['tarball'] = '%s/%s/%s' % (
            MIRROR_URL,
            package,
            tarname
        )

        path = os.path.join(package_path, version)
        with open(path, 'w') as fd:
            log.debug('Writing %s', path)
            fd.write(json.dumps(meta['versions'][version], separators=(',', ':')))

        if os.path.exists(tarpath) and check_sha(tarpath, digest):
            log.debug('SHA1 OK %s', tarpath)
            continue

        if disturl.find('package:5984') != -1:
            disturl = disturl.replace('packages:5984', 'registry.npmjs.org')

        try:
            with open(tarpath, 'wb') as fd:
                res = request(disturl)
                log.debug('Writing %s', tarpath)
                fd.write(res.read())
        except:
            log.exception('Unable to download %s, removing from package.json', disturl)
            del meta['versions'][version]
            continue

        if not check_sha(tarpath, digest):
            log.error('SHA1 Failed for %s, removing from package.json', tarpath)
            os.unlink(tarpath)
            del meta['versions'][version]
            continue

        path = os.path.join(package_path, 'package.json')
        with open(path, 'w') as fd:
            log.debug('Writing %s', path)
            json.dump(meta, fd, separators=(',', ':'))
        return meta


def should_update_package(name, meta):
    package_path = os.path.join(MIRROR_PATH, name.encode('utf8'))
    if os.path.exists(os.path.join(package_path, 'package.json')):
        existing = json.load(open(os.path.join(package_path, 'package.json'), 'r'))
        if 'dist-tags' in meta and 'latest' in meta['dist-tags']:
            latest_version = meta['dist-tags']['latest']
        else:
            latest_version = None

        if 'dist-tags' in existing and 'latest' in existing['dist-tags']:
            current_version = existing['dist-tags']['latest']
        else:
            current_version = None

        if latest_version is None:
            log.debug('%s is unpublished, local version is %s', name, current_version)
            return False

        if current_version == latest_version:
            log.debug('%s is up to date (%s)', name, latest_version)
            return False
        else:
            log.info('Updating existing package %s (%s -> %s)', name, current_version, latest_version)
            return True
    else:
        if not 'dist-tags' in meta:
            log.warning('No local copy of %s and unable to determine latest version from index', name)
            return False
        else:
            log.info('New package %s', name)
            return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true',
                        help='Re-download package.json and update tarballs if checksums are missing or don\'t match the local copy')
    parser.add_argument('--package', nargs='+',
                        help='Specify a package to operate on, rather than all packages. May be specified more than once')
    parser.add_argument('--verbose', action='store_true',
                        help='Log debug messages to stderr')
    parser.add_argument('--quiet', action='store_true',
                        help='Only log errors')
    args = parser.parse_args()

    if args.quiet:
        log.setLevel(logging.ERROR)
    if args.verbose:
        log.setLevel(logging.DEBUG)

    ret = 0
    package_names = args.package
    if not package_names:
        log.info('Downloading package list')
        packages = get_package_index(force_download=args.verify)
    else:
        packages = {}
        for package_name in package_names:
            meta = get_package_info(package_name)
            if meta:
                packages[package_name] = meta
            else:
                log.error('Unable to download package.json for %s', package_name)
                ret = 1

    log.info('%i packages to update', len(packages))

    for package, meta in sorted(packages.iteritems()):
        if package.startswith('_'):
            continue
        if package in PACKAGE_BLACKLIST:
            continue
        if not args.verify and not should_update_package(package, meta):
            log.debug('Skipping update of %s, already up to date', package)
            continue

        if not meta.get('_fullmeta', False):
            meta = get_package_info(package)
        if not meta:
            log.error('Unable to download package.json for %s', package)
            ret = 1
            continue
        
        if not update_package(package, meta):
            ret = 1

    log.debug('Exiting with return code %i', ret)
    return ret


if __name__ == '__main__':
    sys.exit(main())
