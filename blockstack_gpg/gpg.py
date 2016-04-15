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
    Store a public key locally to our app keyring.
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
        assert res.count == 1, "Failed to store key"
    except AssertionError, e:
        log.exception(e)
        log.error("Failed to store key")
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
    try:
        assert res.status == 'ok', "Failed to delete key"
    except AssertionError, e:
        log.exception(e)
        log.error("Failed to delete key '%s'" % key_id)
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

    if sanitized_key_id != fingerprint and fingerprint.endswith( sanitized_key_id ):
        log.debug("Imported key does not match the given ID")
        return False

    else:
        return True


def gpg_export_key( appname, key_id, config_dir=None ):
    """
    Get the ASCII-armored key, given the ID
    """

    assert is_valid_appname(appname)
    config_dir = get_config_dir( config_dir )
    keydir = get_gpg_home( appname, config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=keydir )
    keydat = gpg.export_keys( [key_id] )
    return keydat


def gpg_list_profile_keys( name, proxy=None, wallet_keys=None ):
    """
    List all GPG keys in a user profile:
    Return a list of {'identifier': key ID, 'contentUrl': URL to the key data} on success
    Raise on error
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = blockstack_client.get_default_proxy()

    accounts = list_accounts( name, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in accounts:
        raise Exception("Blockstack error: %s" % accounts['error'] )

    ret = []
    for account in accounts:
        if account['service'] != 'pgp':
            continue 

        ret.append({
            "identifier": account['identifier'],
            "contentUrl": account['contentUrl']
        })

    return ret


def gpg_list_app_keys( blockchain_id, appname, proxy=None, wallet_keys=None ):
    """
    List the set of available GPG keys tagged for a given application.
    The keys will have the format:
        gpg.appname.keyname

    Return list of {'identifier': key ID, 'contentUrl': URL to key data}
    Raise on error
    """

    assert is_valid_appname(appname)

    key_info = []
    key_prefix = "gpg.%s." % appname

    # immutable data key listing (look for keys that start with 'appname:')
    immutable_listing = list_immutable_data( blockchain_id, proxy=proxy )
    if 'error' in immutable_listing:
        raise Exception("Blockstack error: %s" % key_listing['error'])

    for immutable in immutable_listing['data']:
        name = immutable['data_id']
        data_hash = immutable['hash']
        if name.startswith( key_prefix ):
            key_info.append( {
                'identifier': name,
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
                'identifier': name,
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
            blockstack_opener = BlockstackHandler()
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
            key_data = f.read()
            f.close()
        except Exception, e:
            traceback.print_exc()
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


def gpg_app_put_key( blockchain_id, appname, keyname, key_data, txid=None, immutable=False, proxy=None, wallet_keys=None, config_dir=None ):
    """
    Put an application GPG key.
    Stash the private key locally to an app-specific keyring.

    Return {'status': True, 'key_url': ...} on success
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
        key_id = gpg_stash_key( appname, key_data, config_dir=config_dir )
        assert key_id is not None, "Failed to stash key"
    except Exception, e:
        log.exception(e)
        log.error("Failed to store GPG key '%s'" % keyname)
        return {'error': "Failed to store GPG key locally"}

    # get public key... 
    assert is_valid_appname(appname)
    pubkey_data = gpg_export_key( appname, key_id, config_dir=config_dir ) 
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

    keydir = make_gpg_tmphome( "create-app-", config_dir=config_dir )
    gpg = gnupg.GPG( gnupghome=keydir )

    log.debug("Generating GPG key (this may take a while)")

    key_input = gpg.gen_key_input( key_type="RSA", name_email=blockchain_id + "/" + appname, key_length=4096, name_real=keyname )
    key_res = gpg.gen_key( key_input )
    key_id = key_res.fingerprint
    key_data = gpg.export_keys( [key_id] )

    shutil.rmtree(keydir)

    # propagate to blockstack
    add_res = gpg_app_put_key( blockchain_id, appname, keyname, key_data, txid=txid, immutable=immutable, proxy=proxy, wallet_keys=wallet_keys, config_dir=config_dir )
    return add_res

