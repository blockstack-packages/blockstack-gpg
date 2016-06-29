#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
    Blockstack-gpg
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of blockstack-gpg.

    BLockstack-gpg is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-gpg is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with blockstack-gpg.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import traceback
import gnupg
import urllib2
import tempfile
import shutil
import base64
import copy
import json
import re
from ConfigParser import SafeConfigParser

import blockstack_client
from blockstack_client import get_logger, get_config
from blockstack_client import BlockstackHandler
from blockstack_client import list_accounts, list_immutable_data, list_mutable_data
from blockstack_client import make_mutable_data_url, make_immutable_data_url

client = blockstack_client

log = get_logger("blockstack-gpg")

import logging
import urllib
logging.getLogger("gnupg").setLevel( logging.CRITICAL )

DEFAULT_KEY_SERVER = 'pgp.mit.edu'

def get_config_dir( config_dir=None ):
    """
    Get the default configuration directory.
    """
    if config_dir is None:
        config = get_config()
        config_dir = config['dir']

    return config_dir


def is_valid_appname(appname):
    """
    Appname must be url-safe
    """
    # RFC 3896 unreserved characters, except for .
    url_regex = '^[a-zA-Z0-9-_~]+$'
    if re.match(url_regex, appname) is None:
        return False
    else:
        return True


def is_valid_keyname(keyname):
    """
    Keyname must be url-save
    """
    return is_valid_appname(keyname)


def make_gpg_home(appname, config_dir=None):
    """
    Make GPG keyring dir for a particular application.
    Return the path.
    """

    assert is_valid_appname(appname)
    config_dir = get_config_dir( config_dir )
    path = os.path.join( config_dir, "gpgkeys", appname )

    if not os.path.exists(path):
        os.makedirs( path, 0700 )
    else:
        os.chmod( path, 0700 )

    return path


def get_gpg_home( appname, config_dir=None ):
    """
    Get the GPG keyring directory for a particular application.
    Return the path.
    """
    assert is_valid_appname(appname)
    config_dir = get_config_dir( config_dir )
    path = os.path.join( config_dir, "gpgkeys", appname )
    return path 


def get_default_gpg_home( config_dir=None ):
    """
    Get the GPG keyring directory for a particular application.
    Return the path.
    """
    raise Exception("Should ever be called")
    return os.path.expanduser("~/.gnupg")


def make_gpg_tmphome( prefix=None, config_dir=None ):
    """
    Make a temporary directory to hold GPG keys that are not 
    going to be stored to the application's keyring.
    """
    if prefix is None:
        prefix = "tmp"

    config_dir = get_config_dir( config_dir )
    tmppath = os.path.join( config_dir, "tmp" )
    if not os.path.exists( tmppath ):
        os.makedirs( tmppath, 0700 )

    tmpdir = tempfile.mkdtemp( prefix=("%s-" % prefix), dir=tmppath )
    return tmpdir


def gpg_stash_key( appname, key_bin, config_dir=None, gpghome=None ):
    """
    Store a key locally to our app keyring.
    Does NOT put it into a blockchain ID
    Return the key ID on success
    Return None on error
    """

    assert is_valid_appname(appname)
    key_bin = str(key_bin)

    if gpghome is None:
        config_dir = get_config_dir( config_dir )
        keydir = make_gpg_home( appname, config_dir=config_dir )
    else:
        keydir = gpghome

    gpg = gnupg.GPG( gnupghome=keydir )
    res = gpg.import_keys( key_bin )

    try:
        assert res.count == 1, "Failed to store key (%s)" % res
    except AssertionError, e:
        log.exception(e)
        log.error("Failed to store key to %s" % keydir)
        log.debug("res: %s" % res.__dict__)
        log.debug("(%s)\n%s" % (len(key_bin), key_bin))
        return None

    return res.fingerprints[0]


def gpg_unstash_key( appname, key_id, config_dir=None, gpghome=None ):
    """
    Remove a public key locally from our local app keyring
    Return True on success
    Return False on error
    """

    assert is_valid_appname(appname)
    if gpghome is None:
        config_dir = get_config_dir( config_dir )
        keydir = get_gpg_home( appname, config_dir=config_dir )
    else:
        keydir = gpghome

    gpg = gnupg.GPG( gnupghome=keydir )
    res = gpg.delete_keys( [key_id] )
    if res.status == 'Must delete secret key first':
        # this is a private key 
        res = gpg.delete_keys( [key_id], secret=True )

    try:
        assert res.status == 'ok', "Failed to delete key (%s)" % res
    except AssertionError, e:
        log.exception(e)
        log.error("Failed to delete key '%s'" % key_id)
        log.debug("res: %s" % res.__dict__)
        return False

    return True


def gpg_download_key( key_id, key_server, config_dir=None ):
    """
    Download a GPG key from a key server.
    Do not import it into any keyrings.
    Return the ASCII-armored key
    """

    config_dir = get_config_dir( config_dir )
    tmpdir = make_gpg_tmphome( prefix="download", config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=tmpdir )
    recvdat = gpg.recv_keys( key_server, key_id )
    fingerprint = None

    try:
        assert recvdat.count == 1
        assert len(recvdat.fingerprints) == 1
        fingerprint = recvdat.fingerprints[0]

    except AssertionError, e:
        log.exception(e)
        log.error( "Failed to fetch key '%s' from '%s'" % (key_id, key_server))
        shutil.rmtree( tmpdir )
        return None

    keydat = gpg.export_keys( [fingerprint] )
    shutil.rmtree( tmpdir )
    return str(keydat)


def gpg_key_fingerprint( key_data, config_dir=None ):
    """
    Get the key ID of a given serialized key
    Return the fingerprint on success
    Return None on error
    """

    key_data = str(key_data)

    config_dir = get_config_dir( config_dir )
    tmpdir = make_gpg_tmphome( prefix="key_id-", config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=tmpdir )
    res = gpg.import_keys( key_data )

    try:
        assert res.count == 1, "Failed to import key"
        assert len(res.fingerprints) == 1, "Nonsensical GPG response: wrong number of fingerprints"
        fingerprint = res.fingerprints[0]
        shutil.rmtree(tmpdir)
        return fingerprint
    except AssertionError, e:
        log.exception(e)
        shutil.rmtree(tmpdir)
        return None 


def gpg_verify_key( key_id, key_data, config_dir=None ):
    """
    Verify that a given serialized key, when imported, has the given key ID.
    Return True on success
    Return False on error
    """

    key_data = str(key_data)

    config_dir = get_config_dir( config_dir )
    sanitized_key_id = "".join( key_id.upper().split(" ") )
    fingerprint = gpg_key_fingerprint( key_data, config_dir=config_dir )
    if fingerprint is None:
        log.debug("Failed to fingerprint key")
        return False

    if sanitized_key_id != fingerprint and not fingerprint.endswith( sanitized_key_id ):
        log.debug("Imported key does not match the given ID")
        return False

    else:
        return True


def gpg_export_key( appname, key_id, config_dir=None, include_private=False ):
    """
    Get the ASCII-armored key, given the ID
    """

    assert is_valid_appname(appname)
    config_dir = get_config_dir( config_dir )
    keydir = get_gpg_home( appname, config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=keydir )
    keydat = gpg.export_keys( [key_id], secret=include_private )

    if not keydat:
        log.debug("Failed to export key %s from '%s'" % (key_id, keydir))

    assert keydat
    return keydat


def gpg_list_profile_keys( name, proxy=None, wallet_keys=None, config_dir=None ):
    """
    List all GPG keys in a user profile:
    Return a list of {'identifier': key ID, 'contentUrl': URL to the key data} on success
    Raise on error
    Return {'error': ...} on failure
    """

    config_dir = get_config_dir( config_dir )
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )

    if proxy is None:
        proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    accounts = list_accounts( name, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in accounts:
        raise Exception("Blockstack error: %s" % accounts['error'] )

    # extract
    accounts = accounts['accounts']
    ret = []
    for account in accounts:
        if account['service'] != 'pgp':
            continue 

        info = {
            "identifier": account['identifier'],
            "contentUrl": account['contentUrl']
        }

        if 'keyName' in account.keys():
            info['keyName'] = account['keyName']

        ret.append(info)

    return ret


def gpg_list_app_keys( blockchain_id, appname, proxy=None, wallet_keys=None, config_dir=None ):
    """
    List the set of available GPG keys tagged for a given application.
    Return list of {'keyName': key name, 'contentUrl': URL to key data}
    Raise on error
    """

    assert is_valid_appname(appname)

    config_dir = get_config_dir( config_dir )
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )

    if proxy is None:
        proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    key_info = []
    key_prefix = "gpg.%s." % appname

    # immutable data key listing (look for keys that start with 'appname:')
    immutable_listing = list_immutable_data( blockchain_id, proxy=proxy )
    if 'error' in immutable_listing:
        raise Exception("Blockstack error: %s" % immutable_listing['error'])

    for immutable in immutable_listing['data']:
        name = immutable['data_id']
        data_hash = immutable['hash']
        if name.startswith( key_prefix ):
            key_info.append( {
                'keyName': name[len(key_prefix):],
                'contentUrl': make_immutable_data_url( blockchain_id, name, data_hash )
            })

    # mutable data key listing (look for keys that start with 'appname:')
    mutable_listing = list_mutable_data( blockchain_id, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in mutable_listing:
        raise Exception("Blockstack error: %s" % mutable_listing['error'])

    for mutable in mutable_listing['data']:
        name = mutable['data_id']
        version = mutable['version']
        if name.startswith( key_prefix ):
            key_info.append( {
                'keyName': name[len(key_prefix):],
                'contentUrl': make_mutable_data_url( blockchain_id, name, version )
            })

    return key_info


def gpg_fetch_key( key_url, key_id=None, config_dir=None ):
    """
    Fetch a GPG public key from the given URL.
    Supports anything urllib2 supports, as well as blockstack://
    If the URL has no scheme, then assume it's a PGP key server, and use GPG to go get it.
    The key is not accepted into any keyrings.

    Return the key data on success.  If key_id is given, verify the key matches.
    Return None on error, or on failure to carry out any key verification
       (note that resolving blockstack:// URLs automatically verifies keys)
    """

    dat = None

    if "://" in key_url:

        opener = None 
        key_data = None
        from_blockstack = False

        # handle blockstack:// URLs
        if key_url.startswith("blockstack://"):
            blockstack_opener = BlockstackHandler( config_path=os.path.join(config_dir, blockstack_client.CONFIG_FILENAME) )
            opener = urllib2.build_opener( blockstack_opener )
            from_blockstack = True

        elif key_url.startswith("http://") or key_url.startswith("https://"):
            # fetch, but at least try not to look like a bot
            opener = urllib2.build_opener()
            opener.addheaders = [('User-agent', 'Mozilla/5.0')]

        else:
            # defaults
            opener = urllib2.build_opener()

        try:
            f = opener.open( key_url )
            key_data_str = f.read()
            key_data_dict = json.loads(key_data_str)
            assert len(key_data_dict) == 1, "Got multiple keys"
            key_data = str(key_data_dict[key_data_dict.keys()[0]])
            f.close()
        except Exception, e:
            log.exception(e)
            if key_id is not None:
                log.error("Failed to fetch key '%s' from '%s'" % (key_id, key_url))
            else:
                log.error("Failed to fetch key from '%s'" % key_url)
            return None

        # verify, if we have the ID.
        # if we don't have the key ID, then we must be fetching from blockstack 
        # (since then the data will have already been verified by the protocol, using locally-hosted trusted information)
        if not from_blockstack and key_id is None:
            log.error( "No key ID given for key located at %s" % key_url )
            return None

        if key_id is not None:
            rc = gpg_verify_key( key_id, key_data, config_dir=config_dir )
            if not rc:
                log.error("Failed to verify key %s" % key_id)
                return None

        dat = key_data 

    else:
        key_server = key_url
        dat = gpg_download_key( key_id, key_server, config_dir=config_dir )
        assert dat is not None and len(dat) > 0, "BUG: no key data received for '%s' from '%s'" % (key_id, key_url)

    return dat


def gpg_profile_put_key( blockchain_id, key_id, key_name=None, immutable=True, txid=None, key_url=None, use_key_server=True, key_server=None, proxy=None, wallet_keys=None, gpghome=None ):
    """
    Put a local GPG key into a blockchain ID's global account.
    If the URL is not given, the key will be replicated to the default PGP key server and to either immutable (if @immutable) or mutable data.

    Return {'status': True, 'key_url': key_url, 'key_id': key fingerprint, ...} on success
    Return {'error': ...} on error
    """

    if key_name is not None:
        assert is_valid_keyname(key_name)

    if key_server is None:
        key_server = DEFAULT_KEY_SERVER 

    if gpghome is None:
        gpghome = get_default_gpg_home()

    put_res = {}
    extra_fields = {}
    key_data = None
    if key_name is not None:
        extra_fields = {'keyName': key_name}

    if key_url is None:

        gpg = gnupg.GPG( gnupghome=gpghome )

        if use_key_server:
            # replicate key data to default server first 
            res = gpg.send_keys( key_server, key_id )
            if len(res.data) > 0:
                # error 
                log.error("GPG failed to upload key '%s'" % key_id)
                log.error("GPG error:\n%s" % res.stderr)
                return {'error': 'Failed to repliate GPG key to default keyserver'}

        key_data = gpg.export_keys( [key_id] )

        if immutable:
            # replicate to immutable storage 
            immutable_result = client.put_immutable( blockchain_id, key_id, {key_id: key_data}, proxy=proxy, txid=txid, wallet_keys=wallet_keys )
            if 'error' in immutable_result:
                return {'error': 'Failed to store hash of key %s to the blockchain.  Error message: "%s"' % (key_id, immutable_result['error'])}

            else:
                put_res['transaction_hash'] = immutable_result['transaction_hash']
                put_res['zonefile_hash'] = immutable_result['zonefile_hash']

            key_url = client.make_immutable_data_url( blockchain_id, key_id, client.get_data_hash(key_data) )

        else:
            # replicate to mutable storage 
            mutable_name = key_name
            if key_name is None:
                mutable_name = key_id

            mutable_result = client.put_mutable( blockchain_id, key_id, {mutable_name: key_data}, proxy=proxy, wallet_keys=wallet_keys )
            if 'error' in mutable_result:
                return {'error': 'Failed to store key %s.  Error message: "%s"' % (key_id, mutable_result['error'])}

            key_url = client.make_mutable_data_url( blockchain_id, key_id, mutable_result['version'] ) 

    put_account_res = client.put_account( blockchain_id, "pgp", key_id, key_url, proxy=proxy, wallet_keys=wallet_keys, **extra_fields )
    if 'error' in put_account_res:
        return put_account_res

    else:
        put_account_res.update( put_res )
        put_account_res['key_url'] = key_url
        put_account_res['key_id'] = key_id
        return put_account_res


def gpg_profile_delete_key( blockchain_id, key_id, proxy=None, wallet_keys=None ):
    """
    Remove a GPG from a blockchain ID's global account.
    Do NOT remove it from the local keyring.
    Return {'status': True, ...} on success.  May include 'delete_errors' if any specific keys couldn't be removed.
    Return {'error': ...} on error
    """

    res = client.delete_account( blockchain_id, "pgp", key_id, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        return res 

    removed_accounts = res['removed']
    errors = []
    
    # blow away all state 
    for account in removed_accounts:
        if not account.has_key('contentUrl'):
            continue 

        key_url = account['contentUrl']
        if key_url.startswith("blockstack://"):
            # delete
            try:
                res = client.data_delete( key_url, proxy=proxy, wallet_keys=wallet_keys )
                if 'error' in res:
                    errors.append({'key_url': key_url, 'message': res['error']})
            except AssertionError, e:
                log.exception(e)
                log.error("Failed to delete '%s'" % key_url)
                raise

            except Exception, e:
                log.exception(e)
                log.error("Failed to delete '%s'" % key_url)
                continue

    ret = {'status': True}
    if len(errors) > 0:
        ret['delete_errors'] = errors

    return ret

 
def gpg_profile_create_key( blockchain_id, keyname, immutable=True, proxy=None, wallet_keys=None, config_dir=None, gpghome=None, use_key_server=True, key_server=None ):
    """
    Create a new account key.
    Select good default GPG values (4096-bit, RSA/RSA)
    Note that without rngd running, this may take a while.
    Add the new key to the user's account.

    Return {'status': True, 'key_url': ..., 'key_id': ..., } on success
    Return {'error': ...} on error
    """

    assert is_valid_keyname(keyname)

    if config_dir is None:
        config_dir = get_config_dir()

    if gpghome is None:
        gpghome = get_default_gpg_home()

    keydir = make_gpg_tmphome( "create-account-", config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=keydir )

    log.debug("Generating GPG key (this may take a while)")

    key_input = gpg.gen_key_input( key_type="RSA", name_email=blockchain_id, key_length=4096, name_real=keyname )
    key_res = gpg.gen_key( key_input )
    key_id = key_res.fingerprint
    key_data = gpg.export_keys( [key_id] )

    # save the key itself, to the global keyring
    rc = gpg_stash_key( keyname, key_data, gpghome=gpghome ) 
    assert rc, "Failed to store key '%s' (%s)" % (keyname, key_id)
    
    shutil.rmtree(keydir)

    # propagate to blockstack
    add_res = gpg_profile_put_key( blockchain_id, key_id, immutable=immutable, use_key_server=use_key_server, key_server=key_server, key_name=keyname, proxy=proxy, wallet_keys=wallet_keys, gpghome=gpghome )
    return add_res


def gpg_profile_get_key( blockchain_id, keyname, key_id=None, proxy=None, wallet_keys=None, config_dir=None, gpghome=None ):
    """
    Get the profile key
    Return {'status': True, 'key_data': ..., 'key_id': ...} on success
    Return {'error': ...} on error
    """
    
    assert is_valid_keyname( keyname )
    if config_dir is None:
        config_dir = get_config_dir()

    if gpghome is None:
        gpghome = get_default_gpg_home()

    accounts = blockstack_client.list_accounts( blockchain_id, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in accounts:
        return accounts

    # extract
    accounts = accounts['accounts']

    if len(accounts) == 0:
        return {'error': 'No accounts in this profile'}

    all_gpg_accounts = filter( lambda a: a['service'] == 'pgp', accounts )
    if len(all_gpg_accounts) == 0:
        return {'error': 'No GPG accounts in this profile'}
    
    # find the one with this key name 
    gpg_accounts = filter( lambda ga: (ga.has_key('keyName') and ga['keyName'] == keyname) or (key_id is not None and ga['identifier'] == key_id), all_gpg_accounts )
    if len(gpg_accounts) == 0:
        return {'error': 'No such GPG key found'}

    if len(gpg_accounts) > 1:
        return {'error': 'Multiple keys with that name'}

    # go get the key 
    key_data = gpg_fetch_key( gpg_accounts[0]['contentUrl'], key_id=gpg_accounts[0]['identifier'], config_dir=config_dir )
    if key_data is None:
        return {'error': 'Failed to download and verify key'}

    ret = {
        'status': True,
        'key_id': gpg_accounts[0]['identifier'],
        'key_data': key_data
    }

    return ret


def gpg_app_put_key( blockchain_id, appname, keyname, key_data, txid=None, immutable=False, proxy=None, wallet_keys=None, config_dir=None ):
    """
    Put an application GPG key.
    Stash the private key locally to an app-specific keyring.

    Return {'status': True, 'key_url': ..., 'key_data': ...} on success
    Return {'error': ...} on error
    
    If immutable is True, then store the data as an immutable entry (e.g. update the zonefile with the key hash)
    This is a time-consuming operation (on the order of an hour), and you will get back the transaction ID
    on a successful execution.  It is up to you to wait until the transaction is confirmed before using the key.

    Otherwise, the key is stored to mutable storage.
    """

    assert is_valid_appname(appname)
    assert is_valid_keyname(keyname)

    try:
        keydir = make_gpg_home( appname, config_dir=config_dir )
        key_id = gpg_stash_key( appname, key_data, config_dir=config_dir, gpghome=keydir )
        assert key_id is not None, "Failed to stash key"
        log.debug("Stashed app key '%s:%s' (%s) under '%s'" % (appname, keyname, key_id, keydir))
    except Exception, e:
        log.exception(e)
        log.error("Failed to store GPG key '%s'" % keyname)
        return {'error': "Failed to store GPG key locally"}

    # get public key... 
    assert is_valid_appname(appname)
    try:
        pubkey_data = gpg_export_key( appname, key_id, config_dir=config_dir ) 
    except:
        return {'error': 'Failed to load key'}

    fq_key_name = "gpg.%s.%s" % (appname, keyname)
    key_url = None

    if not immutable:
        res = client.put_mutable( blockchain_id, fq_key_name, {fq_key_name: pubkey_data}, txid=txid, proxy=proxy, wallet_keys=wallet_keys )
        if 'error' in res:
            return res

        key_url = client.make_mutable_data_url( blockchain_id, fq_key_name, res['version'] )
    
    else:
        res = client.put_immutable( blockchain_id, fq_key_name, {fq_key_name: pubkey_data}, txid=txid, proxy=proxy, wallet_keys=wallet_keys )
        if 'error' in res:
            return res 

        key_url = client.make_immutable_data_url( blockchain_id, fq_key_name, res['immutable_data_hash'] )

    res['key_url'] = key_url
    res['key_data'] = pubkey_data
    res['key_id'] = gpg_key_fingerprint( pubkey_data, config_dir=config_dir )
    log.debug("Put key %s:%s (%s) to %s" % (appname, keyname, res['key_id'], key_url))
    return res


def gpg_app_delete_key( blockchain_id, appname, keyname, txid=None, immutable=False, proxy=None, wallet_keys=None, config_dir=None ):
    """
    Remove an application GPG key.
    Unstash the local private key.

    Return {'status': True, ...} on success
    Return {'error': ...} on error 

    If immutable is True, then remove the data from the user's zonefile, not profile.  The delete may take
    on the order of an hour to complete on the blockchain.  A transaction ID will be returned to you
    on successful deletion, and it will be up to you to wait for the transaction to get confirmed.
    """
    
    assert is_valid_appname(appname)
    assert is_valid_keyname(keyname)

    fq_key_name = "gpg.%s.%s" % (appname, keyname)
    result = {}
    dead_pubkey_dict = None
    dead_pubkey = None
    key_id = None

    if not immutable:
        # find the key first, so we can get the key ID and then remove it locally 
        dead_pubkey_dict = client.get_mutable( blockchain_id, fq_key_name, proxy=proxy, wallet_keys=wallet_keys )
        if 'error' in dead_pubkey_dict:
            return dead_pubkey_dict

    else:
       # need the key ID so we can unstash locally
        dead_pubkey_dict = client.get_immutable( blockchain_id, None, data_id=fq_key_name, proxy=proxy )
        if 'error' in dead_pubkey_dict:
            return dead_pubkey_dict
    
    dead_pubkey_kv = dead_pubkey_dict['data']
    assert len(dead_pubkey_kv.keys()) == 1, "Not a public key we wrote: %s" % dead_pubkey_kv

    dead_pubkey = dead_pubkey_kv[ dead_pubkey_kv.keys()[0] ]
    key_id = gpg_key_fingerprint( dead_pubkey, config_dir=config_dir )
    assert key_id is not None, "Failed to load pubkey fingerprint"
    
    # actually delete 
    if not immutable:
        result = client.delete_mutable( blockchain_id, fq_key_name, proxy=proxy, wallet_keys=wallet_keys )

    else:
        result = client.delete_immutable( blockchain_id, None, data_id=fq_key_name, wallet_keys=wallet_keys, proxy=proxy )
        
    if 'error' in result:
        return result

    # unstash
    try:
        rc = gpg_unstash_key( appname, key_id, config_dir=config_dir )
        assert rc, "Failed to unstash key"
    except:
        log.warning("Failed to remove private key for '%s'" % key_id )
        result['warning'] = "Failed to remove private key"
        if os.environ.get('BLOCKSTACK_TEST') is not None:
            # make sure this never happens in testing
            raise

    return result


def gpg_app_create_key( blockchain_id, appname, keyname, txid=None, immutable=False, proxy=None, wallet_keys=None, config_dir=None ):
    """
    Create a new application GPG key.
    Use good defaults (RSA-4096)
    Stash it to the app-specific keyring locally.

    Return {'status': True, 'key_url': key_url, 'key_id': key fingerprint, ...} on success
    """

    assert is_valid_appname(appname)
    assert is_valid_keyname(keyname)

    if config_dir is None:
        config_dir = get_config_dir()

    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME)
    if proxy is None:
        proxy = blockstack_client.get_default_proxy(config_path=client_config_path)

    keydir = make_gpg_tmphome( "create-app-", config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=keydir )

    log.debug("Generating GPG key (this may take a while)")

    key_input = gpg.gen_key_input( key_type="RSA", name_email=blockchain_id + "/" + appname, key_length=4096, name_real=keyname )
    key_res = gpg.gen_key( key_input )
    key_id = key_res.fingerprint
    key_data = gpg.export_keys( [key_id], secret=True )

    shutil.rmtree(keydir)

    # propagate to blockstack
    add_res = gpg_app_put_key( blockchain_id, appname, keyname, key_data, txid=txid, immutable=immutable, proxy=proxy, wallet_keys=wallet_keys, config_dir=config_dir )
    return add_res


def gpg_app_get_key( blockchain_id, appname, keyname, immutable=False, key_id=None, key_hash=None, key_version=None, proxy=None, config_dir=None ):
    """
    Get an app-specific GPG key.
    Return {'status': True, 'key_id': ..., 'key': ..., 'app_name': ...} on success
    return {'error': ...} on error
    """

    assert is_valid_appname(appname)
    assert is_valid_keyname(keyname)

    if config_dir is None:
        config_dir = get_config_dir()

    fq_key_name = "gpg.%s.%s" % (appname, keyname)
    key_url = None 

    if immutable:
        # try immutable
        key_url = blockstack_client.make_immutable_data_url( blockchain_id, fq_key_name, key_hash )

    else:
        # try mutable 
        key_url = blockstack_client.make_mutable_data_url( blockchain_id, fq_key_name, key_version )

    log.debug("fetch '%s'" % key_url)
    key_data = gpg_fetch_key( key_url, key_id=key_id, config_dir=config_dir )
    if key_data is None:
        return {'error': 'Failed to fetch key'}

    if key_id is None:
        key_id = gpg_key_fingerprint( key_data, config_dir=config_dir )

    ret = {
        'status': True,
        'key_id': key_id,
        'key_data': key_data,
        'app_name': appname
    }

    return ret


def gpg_sign( path_to_sign, sender_key_info, config_dir=None, passphrase=None ):
    """
    Sign a file on disk.
    @sender_key_info should be the result of gpg_app_get_key
    Return {'status': True, 'sig': ...} on success
    Return {'error': ...} on error
    """

    if config_dir is None:
        config_dir = get_config_dir()

    # ingest keys 
    tmpdir = make_gpg_tmphome( prefix="sign", config_dir=config_dir )

    try:
        sender_privkey = gpg_export_key( sender_key_info['app_name'], sender_key_info['key_id'], include_private=True, config_dir=config_dir )
    except Exception, e:
        log.exception(e)
        shutil.rmtree(tmpdir)
        return {'error': 'No such private key'}

    res = gpg_stash_key( "sign", sender_privkey, config_dir=config_dir, gpghome=tmpdir )
    if res is None:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to load sender private key'}

    # do the signature
    gpg = gnupg.GPG( gnupghome=tmpdir )
    res = None

    with open(path_to_sign, "r") as fd_in:
        res = gpg.sign_file( fd_in, keyid=sender_key_info['key_id'], passphrase=passphrase, detach=True )

    shutil.rmtree(tmpdir)

    if not res:
        log.debug("sign_file error: %s" % res.__dict__)
        log.debug("signer: %s" % sender_key_info['key_id'])
        return {'error': 'Failed to sign data'}
    
    return {'status': True, 'sig': res.data }


def gpg_verify( path_to_verify, sigdata, sender_key_info, config_dir=None ):
    """
    Verify a file on disk was signed by the given sender.
    @sender_key_info should be the result of gpg_app_get_key
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if config_dir is None:
        config_dir = get_config_dir()

    # ingest keys 
    tmpdir = make_gpg_tmphome( prefix="verify", config_dir=config_dir )
    res = gpg_stash_key( "verify", sender_key_info['key_data'], config_dir=config_dir, gpghome=tmpdir )
    if res is None:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to stash key %s' % sender_key_info['key_id']}

    # stash detached signature 
    fd, path = tempfile.mkstemp( prefix=".sig-verify-" )
    f = os.fdopen(fd, "w")
    f.write( sigdata )
    f.flush()
    os.fsync(f.fileno())
    f.close()

    # verify 
    gpg = gnupg.GPG( gnupghome=tmpdir )

    with open(path, "r") as fd_in:
        res = gpg.verify_file( fd_in, data_filename=path_to_verify )

    shutil.rmtree(tmpdir)
    try:
        os.unlink(path)
    except:
        pass

    if not res:
        log.debug("verify_file error: %s" % res.__dict__)
        return {'error': 'Failed to decrypt data'}

    log.debug("verification succeeded from keys in %s" % config_dir)
    return {'status': True}


def gpg_encrypt( fd_in, path_out, sender_key_info, recipient_key_infos, passphrase=None, config_dir=None ):
    """
    Encrypt a stream of data for a set of keys.
    @sender_key_info and @recipient_key_infos should be data returned by gpg_app_get_key.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if config_dir is None:
        config_dir = get_config_dir()

    # ingest keys 
    tmpdir = make_gpg_tmphome( prefix="encrypt", config_dir=config_dir )
    for key_info in recipient_key_infos:
        res = gpg_stash_key( "encrypt", key_info['key_data'], config_dir=config_dir, gpghome=tmpdir )
        if res is None:
            shutil.rmtree(tmpdir)
            return {'error': 'Failed to stash key %s' % key_info['key_id']}

    # copy over our key
    try:
        sender_privkey = gpg_export_key( sender_key_info['app_name'], sender_key_info['key_id'], include_private=True, config_dir=config_dir )
    except Exception, e:
        log.exception(e)
        shutil.rmtree(tmpdir)
        return {'error': 'No such private key'}

    res = gpg_stash_key( "encrypt", sender_privkey, config_dir=config_dir, gpghome=tmpdir )
    if res is None:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to load sender private key'}

    recipient_key_ids = [r['key_id'] for r in recipient_key_infos]

    # do the encryption
    gpg = gnupg.GPG( gnupghome=tmpdir )
    res = gpg.encrypt_file( fd_in, recipient_key_ids, sign=sender_key_info['key_id'], passphrase=passphrase, output=path_out, always_trust=True )
    shutil.rmtree(tmpdir)

    if res.status != 'encryption ok':
        log.debug("encrypt_file error: %s" % res.__dict__)
        log.debug("recipients: %s" % recipient_key_ids)
        log.debug("signer: %s" % sender_key_info['key_id'])
        return {'error': 'Failed to encrypt data'}
    
    return {'status': True}


def gpg_decrypt( fd_in, path_out, sender_key_info, my_key_info, passphrase=None, config_dir=None ):
    """
    Decrypt a stream of data using key info 
    for a private key we own.
    @my_key_info and @sender_key_info should be data returned by gpg_app_get_key
    Return {'status': True} on succes
    Return {'error': ...} on error
    """

    if config_dir is None:
        config_dir = get_config_dir()

    # ingest keys 
    tmpdir = make_gpg_tmphome( prefix="decrypt", config_dir=config_dir )
    res = gpg_stash_key( "decrypt", sender_key_info['key_data'], config_dir=config_dir, gpghome=tmpdir )
    if res is None:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to stash key %s' % sender_key_info['key_id']}

    try:
        my_privkey = gpg_export_key( my_key_info['app_name'], my_key_info['key_id'], include_private=True, config_dir=config_dir )
    except:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to load local private key for %s' % my_key_info['key_id']}

    res = gpg_stash_key( "decrypt", my_privkey, config_dir=config_dir, gpghome=tmpdir )
    if res is None:
        shutil.rmtree(tmpdir)
        return {'error': 'Failed to load private key'}

    # do the decryption 
    gpg = gnupg.GPG( gnupghome=tmpdir )
    res = gpg.decrypt_file( fd_in, passphrase=passphrase, output=path_out, always_trust=True )
    shutil.rmtree(tmpdir)

    if res.status != 'decryption ok':
        log.debug("decrypt_file: %s" % res.__dict__)
        return {'error': 'Failed to decrypt data'}

    log.debug("decryption succeeded from keys in %s" % config_dir)
    return {'status': True}

