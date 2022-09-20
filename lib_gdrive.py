# -*- coding: utf-8 -*-
#########################################################
# python
from __future__ import print_function

import os, sys, traceback, re, json, threading, time, shutil
from datetime import datetime, timedelta
# third-party
import requests
# third-party
from flask import request, render_template, jsonify, redirect
from sqlalchemy import or_, and_, func, not_, desc
import random
from httplib2 import Http

# sjva 공용
from framework import db, scheduler, path_data, socketio, SystemModelSetting, app
from framework.util import Util
from framework.common.util import headers, get_json_with_auth_session
from framework.common.plugin import LogicModuleBase, default_route_socketio
from tool_expand import ToolExpandFileProcess

# googledrive api
try:
    from oauth2client.service_account import ServiceAccountCredentials
except ImportError:
    os.system("{} install --upgrade oauth2client".format(app.config['config']['pip']))
    from oauth2client.service_account import ServiceAccountCredentials

try:
    import pickle
    from googleapiclient.discovery import build
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
except ImportError:
    os.system("{} install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib".format(app.config['config']['pip']))
    import pickle
    from googleapiclient.discovery import build
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request


# anytree
try:
    from anytree import Node, PreOrderIter
except ImportError:
    os.system("{} install anytree".format(app.config['config']['pip']))
    from anytree import Node, PreOrderIter

# 패키지
from .plugin import P
logger = P.logger


#########################################################

class LibGdrive(object):
    scope = ['https://www.googleapis.com/auth/drive']
    token_uri = 'https://www.googleapis.com/oauth2/v3/token'
    service     = None
    sa_service  = None
    json_list   = []
    current_flow = None

    @classmethod
    def auth_step1(cls, credentials='credentials.json', token='token.pickle',):
        flow = InstalledAppFlow.from_client_secrets_file(credentials, cls.scope, redirect_uri='urn:ietf:wg:oauth:2.0:oob')
        cls.current_flow = flow
        return flow.authorization_url()

    @classmethod
    def auth_step2(cls, code, token='token.pickle',):
        try:
            cls.current_flow.fetch_token(code=code)
            creds = cls.current_flow.credentials
            with open(token, 'wb') as t:
                pickle.dump(creds, t)

            cls.service = build('drive', 'v3', credentials=creds)
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return False

    @classmethod
    def user_authorize(cls, token='token.pickle',):
        try:
            creds = None
            if os.path.exists(token):
                with open(token, 'rb') as tokenfile:
                    creds = pickle.load(tokenfile)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else: return False

                with open(token, 'wb') as t:
                    pickle.dump(creds, t)

            cls.service = build('drive', 'v3', credentials=creds)
            return True
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return False

    @classmethod
    def sa_authorize(cls, json_path, return_service=False, scopes=None, impersonate=None):
        if not os.path.exists(json_path):
            logger.error('can not recognize gdrive_auth_path(%s)', json_path)
            data = {'type':'warning', 'msg':'인증파일(.json) 경로를 확인해주세요.'}
            socketio.emit('notify', data, namespace='/framework', broadcast=True)
            if return_service: return None
            else: return False

        if os.path.isdir(json_path):
            cls.json_list = cls.get_all_jsonfiles(json_path)
            logger.debug('load json list(%d)', len(cls.json_list))
            json_file = ''.join(random.sample(cls.json_list, 1))
        else:
            json_file = json_path
            cls.json_list = [json_path]

        logger.debug('json_file: %s', json_file)
        scope = scopes if scopes != None else cls.scope

        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, scope)
            if impersonate != None:
                delegated_credentials = credentials.create_delegated(impersonate)
                if return_service:
                    service = build('drive', 'v3', credentials=delegated_credentials)
                    return service
                else:
                    cls.sa_service = build('drive', 'v3', http=delegated_credentials)
                    return True
            else:
                if return_service:
                    service = build('drive', 'v3', credentials=credentials)
                    return service
                else:
                    cls.sa_service = build('drive', 'v3', credentials=credentials)
                    return True
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            if return_service: return None
            else: return False

 
    @classmethod
    def sa_authorize_by_info(cls, json_data, return_service=False, scopes=None, impersonate=None):
        scope = scopes if scopes != None else cls.scope
        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_dict(json_data, scope)
            if impersonate != None:
                delegated_credentials = credentials.create_delegated(impersonate)
                if return_service:
                    service = build('drive', 'v3', credentials=delegated_credentials)
                    return service
                else:
                    cls.sa_service = build('drive', 'v3', http=delegated_credentials)
                    return True
            else:
                if return_service:
                    service = build('drive', 'v3', credentials=credentials)
                    return service
                else:
                    cls.sa_service = build('drive', 'v3', credentials=credentials)
                    return True
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            if return_service: return None
            else: return False

    @classmethod
    def sa_auth_by_creds(cls, creds):
        try:
            return build('drive', 'v3', credentials=creds)
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_access_token_for_gds(cls, json_data, scopes, impersonate):
        try:
            creds = None
            creds = ServiceAccountCredentials.from_json_keyfile_dict(json_data, scopes).create_delegated(impersonate)
            if creds.access_token == '' or creds.access_token == None or creds.access_token_expired:
                logger.info('try to access_token refresh')
                creds.refresh(Http())
            return creds.access_token
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_credentials_for_gds(cls, sa_info, scopes, impersonate):
        try:
            creds = None
            creds = ServiceAccountCredentials.from_json_keyfile_dict(sa_info, scopes).create_delegated(impersonate)
            if creds.access_token == '' or creds.access_token == None or creds.access_token_expired:
                logger.info('try to access_token refresh')
                creds.refresh(Http())
            return creds
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def sa_get_token_for_gds(cls, sa_info, scopes, impersonate):
        try:
            creds = None
            creds = ServiceAccountCredentials.from_json_keyfile_dict(sa_info, scopes).create_delegated(impersonate)
            if creds.access_token == '' or creds.access_token == None or creds.access_token_expired:
                logger.info('try to access_token refresh')
                creds.refresh(Http())
            return creds.access_token
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def sa_authorize_for_multiple_connection(cls, json_path, max_connection):
        services = []
        if not os.path.exists(json_path):
            logger.error('can not recognize gdrive_auth_path(%s)', json_path)
            data = {'type':'warning', 'msg':'인증파일(.json) 경로를 확인해주세요.'}
            socketio.emit('notify', data, namespace='/framework', broadcast=True)
            return None

        if os.path.isdir(json_path):
            cls.json_list = cls.get_all_jsonfiles(json_path)
            logger.debug('load json list(%d)', len(cls.json_list))
            json_files = random.sample(cls.json_list, max_connection)
        else:
            logger.error('need multiple json files(%s)', json_path)
            data = {'type':'warning', 'msg':'인증파일(.json)들이 존재하는 폴더경로를 지정해주세요.'}
            socketio.emit('notify', data, namespace='/framework', broadcast=True)
            return None

        try:
            for json_file in json_files:
                credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, cls.scope)
                services.append(build('drive', 'v3', credentials=credentials))
            return services
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def auth_by_rclone_remote(cls, remote, set_service=False):
        try:
            try:
                from google.oauth2.credentials import Credentials as OAuth2Credentials
            except ImportError:
                os.system("{} install google-oauth".format(app.config['config']['pip']))
                from google.oauth2.credentials import Credentials as OAuth2Credentials

            # SA 
            if 'service_account_file' in remote:
                return cls.sa_authorize(remote['service_account_file_path'], return_service=True)

            for key in ['client_id', 'client_secret']:
                if key not in remote:
                    logger.error(f'{key} is required: check rclone.conf')
                    return None

            client_id = remote['client_id']
            client_secret = remote['client_secret']
            token = remote['token']['access_token']
            refresh_token = remote['token']['refresh_token']

            scopes = ['https://www.googleapis.com/auth/{}'.format(remote['scope'])]
            creds = OAuth2Credentials(token,
                    refresh_token=refresh_token,
                    id_token=None,
                    token_uri=cls.token_uri,
                    client_id=client_id,
                    client_secret=client_secret,
                    scopes=scopes)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logger.debug('credential expired. refresh')
                    creds.refresh(Request())

            service = build('drive', 'v3', credentials=creds)
            if set_service: cls.service = service
            return service

        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def switch_service_account(cls, service=None):
        while True:
            try:
                scope = ['https://www.googleapis.com/auth/drive']
                json_file = ''.join(random.sample(cls.json_list, 1))
                credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, cls.scope)
                if service != None:
                    service = build('drive', 'v3', credentials=credentials)
                    return service
                else:
                    cls.sa_service = build('drive', 'v3', credentials=credentials)
                    return cls.sa_service
            except Exception as e: 
                logger.error('Exception:%s', e)
                logger.error(traceback.format_exc())
                if len(cls.json_list) == 1: return None

    @classmethod
    def create_shortcut(cls, shortcut_name, target_folder_id, parent_folder_id, service=None):
        try:
            ret = {}
            logger.debug('create_shortcut: shortcut(%s,%s,%s)', shortcut_name, target_folder_id, parent_folder_id)

            shortcut_metadata = {
                'name': shortcut_name,
                'mimeType': 'application/vnd.google-apps.shortcut',
                'shortcutDetails': {
                    'targetId': target_folder_id
                },
                'parents': [parent_folder_id]
            }
            svc = cls.sa_service if service == None else service
            shortcut = svc.files().create(body=shortcut_metadata, 
                    fields='id,shortcutDetails', supportsAllDrives=True).execute()

            #logger.debug(json.dumps(shortcut, indent=2))
            logger.debug('create_shortcut: shortcut_created: %s', shortcut_name)
            ret['ret'] = 'success'
            ret['data'] = shortcut
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)

    @classmethod
    def get_all_jsonfiles(cls, target_path):
        file_list = []

        for (path, dir, files) in os.walk(target_path):
            for filename in files:
                ext = os.path.splitext(filename)[-1]
                if ext == '.json':
                    file_list.append(os.path.join(path, filename))

        return file_list

    @classmethod
    def get_file_info(cls, folder_id, fields=None, service=None):
        try:
            ret = {}
            data = {}
            str_fields = 'id, name, mimeType, parents, trashed'
            if fields != None: str_fields = ",".join(fields)
            svc = service if service != None else cls.sa_service
            info = svc.files().get(fileId=folder_id, supportsAllDrives=True,fields=str_fields).execute()
            for field in str_fields.split(','): data[field.strip()] = info.get(field.strip())
            ret['ret'] = 'success'
            ret['data'] = data
            logger.debug('get_file_info: id(%s)', folder_id)
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret

    @classmethod
    def get_file_info_with_name_parent(cls, name, parent_id, service=None):
        try:
            ret = {}
            data = {}
            str_fields = 'id, name, mimeType, parents'
            svc = cls.sa_service if service == None else service

            query = u"mimeType='application/vnd.google-apps.folder' and name='{}' and '{}' in parents".format(name, parent_id)
            r = svc.files().list(q=query, supportsAllDrives=True, includeTeamDriveItems=True).execute()
            for item in r.get('files', []):
                data['id'] = item.get('id')
                data['name'] = item.get('name')
                data['mimeType'] = item.get('mimeType')
                data['parents'] = item.get('parents')
                break
            ret['ret'] = 'success'
            ret['data'] = data
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret


    @classmethod
    def get_gdrive_full_path(cls, folder_id, service=None):
        try:
            pathes = []
            parent_id = folder_id
            svc = cls.sa_service if service == None else service
            while True:
                r = svc.files().get(fileId=parent_id, supportsAllDrives=True,
                        fields='id, name, mimeType, parents').execute()

                #logger.debug(json.dumps(r, indent=2))
                if 'parents' in r:
                    parent_id = r['parents'][0]
                    pathes.append(r['name'])
                else:
                    # team drive 예외처리
                    if r['name'] == 'Drive' and len(r['id']) < 32: break
                    pathes.append(r['name'])
                    break

            pathes.append('')
            pathes.reverse()
            full_path = u'/'.join(pathes)
            logger.debug('get_gdrive_full_path: %s(%s)', full_path, folder_id)
            return full_path
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            return None

    @classmethod
    def get_gdrive_full_path_except_me(cls, folder_id, service=None):
        try:
            pathes = []
            parent_id = folder_id
            svc = cls.sa_service if service == None else service
            while True:
                r = service.files().get(fileId=parent_id, supportsAllDrives=True, fields='id, name, mimeType, parents').execute()
                if 'parents' in r:
                    logger.debug('fodler_id: %s, parent_id: %s', folder_id, parent_id)
                    parent_id = r['parents'][0]
                    if parent_id != folder_id:
                        pathes.append(r['name'])
                else:
                    # team drive 예외처리
                    if r['name'] == 'Drive' and len(r['id']) < 32: break
                    pathes.append(r['name'])
                    break
    
            pathes.append('')
            pathes.reverse()
            full_path = u'/'.join(pathes)
            logger.debug('get_gdrive_full_path_except_me: %s(%s)', full_path, folder_id)
            return full_path
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            return None

    @classmethod
    def get_all_folders_in_folder(cls, root_folder_id, last_searched_time, service=None):
        try:
            child_folders = {}
            page_token = None
            if last_searched_time == None:
                query = "mimeType='application/vnd.google-apps.folder' \
                        and '{r}' in parents".format(r=root_folder_id)
            else:
                time_str = last_searched_time.strftime('%Y-%m-%dT%H:%M:%S+09:00')
                query = "mimeType='application/vnd.google-apps.folder' \
                        and '{r}' in parents and modifiedTime>'{t}'".format(r=root_folder_id, t=time_str)
    
            svc = cls.sa_service if service == None else service
            while True:
                r = svc.files().list(q=query,
                        spaces='drive',
                        pageSize=1000,
                        supportsAllDrives=True, includeTeamDriveItems=True,
                        fields='nextPageToken, files(id, name, parents, modifiedTime)',
                        pageToken=page_token).execute()
        
                folders = r.get('files', [])
                page_token = r.get('nextPageToken', None)
    
                for folder in folders:
                    child_folders[folder['id']] = folder['parents'][0]
                if page_token == None: break
        
            logger.debug('get_all_folders_in_folder: %d items found', len(child_folders))
            return child_folders
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            return None

    @classmethod
    def get_subfolders_of_folder(cls, folder_to_search, all_folders, service=None):
        temp_list = [k for k, v in all_folders.items() if v == folder_to_search]
        for sub_folder in temp_list:
            yield sub_folder
            for x in cls.get_subfolders_of_folder(sub_folder, all_folders, service=service):
                yield x

    @classmethod
    def get_all_folders(cls, root_folder_id, last_searched_time, service=None):
        all_folders = cls.get_all_folders_in_folder(root_folder_id, last_searched_time, service=service)
        target_folder_list = []
        for folder in cls.get_subfolders_of_folder(root_folder_id, all_folders, service=service):
            target_folder_list.append(folder)
        return target_folder_list

    @classmethod
    def get_children(cls, target_folder_id, fields=None, service=None, time_after=None, order_by='createdTime desc'):
        children = []
        try:
            svc = service if service != None else cls.sa_service
            page_token = None
            if time_after == None:
                query = "'{}' in parents".format(target_folder_id)
            else:
                query = "modifiedTime >= '{}' and '{}' in parents".format(cls.get_gdrive_time_str(_datetime=time_after), target_folder_id)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents, trashed)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            while True:
                try:
                    r = svc.files().list(q=query, 
                            spaces='drive', 
                            pageSize=1000, 
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            fields=str_fields, 
                            orderBy=order_by,
                            pageToken=page_token).execute()
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('get_children(%s): %d items found', target_folder_id, len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_children_for_sa(cls, target_folder_id, fields=None, service=None, time_after=None, order_by='createdTime desc'):
        children = []
        try:
            svc = service if service != None else cls.sa_service
            page_token = None
            if time_after == None:
                query = "'{}' in parents".format(target_folder_id)
            else:
                query = "modifiedTime >= '{}' and '{}' in parents".format(cls.get_gdrive_time_str(_datetime=time_after), target_folder_id)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents, trashed)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            while True:
                try:
                    r = svc.files().list(q=query, 
                            corpora='allDrives',
                            pageSize=1000, 
                            includeItemsFromAllDrives=True,
                            supportsAllDrives=True,
                            fields=str_fields, 
                            orderBy=order_by,
                            pageToken=page_token).execute()
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('get_children(%s): %d items found', target_folder_id, len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None


    @classmethod
    def get_children_folders(cls, target_folder_id, service=None, time_after=None):
        children = []
        try:
            page_token = None
            if time_after == None:
                query = "mimeType='application/vnd.google-apps.folder'\
                        and '{}' in parents".format(target_folder_id)
            else:
                query = "mimeType='application/vnd.google-apps.folder'\
                        and modifiedTime >= '{}'\
                        and '{}' in parents".format(cls.get_gdrive_time_str(_datetime=time_after), target_folder_id)

            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = svc.files().list(q=query, 
                            spaces='drive',
                            pageSize=1000,
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            fields='nextPageToken, files(id, name, parents, mimeType, trashed)',
                            pageToken=page_token).execute()
                
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None
    
            logger.debug('get_children_folders(%s): %d items found', target_folder_id, len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def get_fileid_from_path(cls, root_folder_id, full_path, service=None):
        try:
            logger.debug(f'get_fileid: req {root_folder_id}, {full_path}')
            pathes = list(filter(None, full_path.split('/')))
            parent_id = root_folder_id
            file_id = None
            for dname in pathes:
                children = []
                query = f"name='{dname}' and '{parent_id}' in parents"
                #logger.debug(f'query: {query}')

                svc = service if service != None else cls.sa_service
                try:
                    r = svc.files().list(q=query, 
                            spaces='drive',
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            fields='files(id, name, parents, mimeType, trashed, shortcutDetails)').execute()
                    child = r.get('files', [])[0]
                    #logger.debug(f'ret={r}')
                    if dname == pathes[-1]: # 경로상 마지막 위치의 경우
                        file_id = child['id']
                        break

                    if child['mimeType'] == 'application/vnd.google-apps.shortcut':
                        parent_id = child['shortcutDetails']['targetId']
                    else: 
                        parent_id = child['id']

                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None
    
            logger.debug(f'get_fileid: ret {full_path}, {file_id}')
            return file_id

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_children_folders_with_parents(cls, parents, service=None):
        children = []
        try:
            page_token = None
            parents_str = " in parents or ".join(["'"+x+"'" for x in parents]) + " in parents"
            query = "mimeType='application/vnd.google-apps.folder' and ({})".format(parents_str)
            logger.debug(query)

            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = svc.files().list(q=query, 
                            spaces='drive',
                            corpora='allDrives',
                            includeItemsFromAllDrives=True,
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            pageSize=1000,
                            fields='nextPageToken, files(id, name, parents, mimeType)',
                            pageToken=page_token).execute()
                
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('get_children_folders: %d items found', len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def get_children_with_mtypes(cls, target_folder_id, mtypes=None, fields=None, service=None, time_after=None, order_by='createdTime desc'):
        children = []
        try:
            svc = service if service != None else cls.sa_service
            page_token = None
            if time_after == None:
                query = "'{}' in parents".format(target_folder_id)
            else:
                query = "modifiedTime >= '{}' and '{}' in parents".format(cls.get_gdrive_time_str(_datetime=time_after), target_folder_id)
            
            if mtypes != None:
                if type(mtypes) == list and len(mtypes) > 0:
                    query_mtypes = " and (mimeType contains '" + "' or mimeType contains '".join(mtypes)+"')"
                    query = query + query_mtypes
                elif type(mtypes) == str:
                    query_mtypes = " and mimeType contains '{}'".format(mtypes)
                    query = query + query_mtypes

            str_fields = 'nextPageToken, files(id, name, mimeType, parents, trashed)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            while True:
                try:
                    r = svc.files().list(q=query, 
                            #spaces='drive', 
                            pageSize=1000, 
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            fields=str_fields, 
                            orderBy=order_by,
                            pageToken=page_token).execute()
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('get_children(%s): %d items found', target_folder_id, len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_children2(cls, parents, mtypes=None, fields=None, service=None, time_after=None, order_by='createdTime desc', limit=100):
        children = []
        try:
            svc = service if service != None else cls.sa_service
            page_token = None
            query = ''; query_mtime = ''; query_mtypes = ''
            if time_after != None: query_mtime = " and modifiedTime >= '{}'".format(cls.get_gdrive_time_str(_datetime=time_after))
            #query_parents = " and (parents in '" + "' or parents in '".join(parents)+"')"
            if mtypes != None:
                if type(mtypes) == list and len(mtypes) > 0:
                    query_mtypes = " and (mimeType contains '" + "' or mimeType contains '".join(mtypes)+"')"
                elif type(mtypes) == str:
                    query_mtypes = " and mimeType contains '{}'".format(mtypes)

            str_fields = 'nextPageToken, files(id, name, mimeType, parents, trashed)'

            pos = 0
            while pos < len(parents):
                #query_parents = "(parents in '" + "' or parents in '".join(parents[pos:pos+limit])+"')"
                query_parents = "('" + "' in parents or '".join(parents[pos:pos+limit])+"' in parents)"
                #logger.debug(f'query_parents: ({query_parents}')
                query = query_parents + query_mtime + query_mtypes
                #logger.debug(f'{pos}:{limit}:query:[{query}]')
                if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
                while True:
                    try:
                        r = svc.files().list(q=query, 
                                corpora='allDrives',
                                pageSize=1000, 
                                supportsAllDrives=True, includeItemsFromAllDrives=True,
                                fields=str_fields, 
                                orderBy=order_by,
                                pageToken=page_token).execute()
                        page_token = r.get('nextPageToken', None)
                        for child in r.get('files', []): children.append(child)
                        if page_token == None: break
                    except Exception as e:
                        logger.error('Exception:%s', e)
                        logger.error(traceback.format_exc())
                        return None
                pos = pos + limit

            logger.debug('get_children2: %d items found', len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_gdrive_time_str(cls, _datetime = None, _delta_min = None):
        utc_delta = datetime.utcnow() - datetime.now()
        if _datetime == None: _date_time = datetime.now()
        if _delta_min == None: _delta_min = 0
        tt  = _datetime + utc_delta - timedelta(minutes=_delta_min)
        return tt.isoformat('T') + 'Z'
        #return tt.strftime('%Y-%m-%dT%H:%M:%S+09:00')

    @classmethod
    def get_children_video_files(cls, parent_folder_id, time_after=None, service=None):
        children = []
        try:
            page_token = None
            if time_after == None:
                query = "mimeType contains 'video/' and '{}' in parents".format(parent_folder_id)
            else:
                query = "mimeType contains 'video/'\
                        and '{}' in parents\
                        and modifiedTime >= '{}'".format(parent_folder_id, cls.get_gdrive_time_str(_datetime=time_after))

            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = svc.files().list(q=query, 
                            spaces='drive',
                            pageSize=1000,
                            supportsAllDrives=True, includeTeamDriveItems=True,
                            fields='nextPageToken, files(id, name, parents, mimeType)',
                            pageToken=page_token).execute()

                    logger.debug(json.dumps(r, indent=2))
                    for child in r.get('files', []): children.append(child)
                    page_token = r.get('nextPageToken', None)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('get_children_video_files: %d items found', len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def populate_tree(cls, parent, parent_id, depth, service=None):
        try:
            children = cls.get_children_folders(parent_id, service=service)
            children_nodes = []
            if len(children) > 0:
                for child in children:
                    node = Node(child['name'], parent=parent, id=child['id'], parent_id=parent_id, mime_type=child['mimeType'])
                    children_nodes.append(node)

            if depth-1 == 0: return
            for node in children_nodes:
                cls.populate_tree(node, node.id, depth-1, service=service)

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_all_subfolders(cls, root_folder_id, name=None, max_depth=1, service=None, full_path=False):
        try:
            if full_path:
                path_of_root = cls.get_gdrive_full_path_except_me(root_folder_id, service=service)
            if name == None:
                root_folder_info = cls.get_file_info(root_folder_id, service=service)
                name = root_folder_info['data']['name']
            root = Node(name, id=root_folder_id)
            cls.populate_tree(root, root_folder_id, max_depth, service=service)

            folder_list = []
            for node in PreOrderIter(root, filter_=lambda n:n.height == 0):
                if node == root: break
                folder = {}
                folder['name'] = node.name
                folder['folder_id'] = node.id
                folder['parent_folder_id'] = node.parent_id
                folder['mime_type'] = node.mime_type
                if full_path:
                    folder['full_path'] = path_of_root + '/' + '/'.join([x.name for x in list(node.path)])
                logger.debug('add to list: %s,%s,%s', node.name, node.id, node.mime_type)
                folder_list.append(folder)

            logger.debug('get_all_subfolders: %d items found', len(folder_list))
            return folder_list
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_target_subfolders(cls, root_folder_id, target_depth=1, service=None):
        try:
            root = Node('root', id=root_folder_id)
            cls.populate_tree(root, root_folder_id, target_depth, service=service)
            ret = {}
            ret['root_folder_id'] = root_folder_id

            folder_list = []
            for node in PreOrderIter(root, filter_=lambda n:n.height == 0):
                if node == root: break
                folder = {}
                folder['name'] = node.name
                folder['folder_id'] = node.id
                folder_list.append(folder)

            logger.debug('get_target_subfolders: %d items found', len(folder_list))
            ret['target_folders'] = folder_list
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None


    @classmethod
    def create_sub_folder(cls, name, parent_folder_id, service=None):
        try:
            ret = {}
            parent_id = parent_folder_id
            meta = {'name': name, 'mimeType': 'application/vnd.google-apps.folder', 'parents': [parent_id]}
            svc = service if service != None else cls.service
            newfolder = svc.files().create(body=meta, fields='id', supportsAllDrives=True).execute()

            #logger.debug(newfolder)
            data = {'name':name, 'folder_id':newfolder.get('id'), 'parent_folder_id':parent_id}
            ret['ret'] = 'success'
            ret['data'] = data
            return ret

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error', 'msg':str(e)}

    @classmethod
    def delete_file(cls, file_id, service=None, trash=False):
        try:
            ret = {}
            svc = cls.service if service == None else service
            if trash:
                body = {'trashed': True}
                data = svc.files().update(fileId=file_id,body=body,supportsAllDrives=True).execute()
            else: data = svc.files().delete(fileId=file_id,supportsAllDrives=True).execute()
            ret['ret'] = 'success'
            ret['data'] = data
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def move_file(cls, file_id, old_parent_id, new_parent_id, service=None, newname=None):
        try:
            ret = {}
            body = None
            if newname != None: body = {'name':newname}
            svc = service if service != None else cls.service
            if body != None:
                res = svc.files().update(fileId=file_id, 
                        addParents=new_parent_id, 
                        removeParents=old_parent_id, 
                        body=body,
                        supportsAllDrives=True,
                        fields='id,parents').execute()
            else:
                res = svc.files().update(fileId=file_id, 
                        addParents=new_parent_id, 
                        removeParents=old_parent_id, 
                        supportsAllDrives=True,
                        fields='id,parents').execute()
            ret['ret'] = 'success'
            data = {'folder_id':res.get('id'), 'parent_folder_id':res.get('parents')[0]}
            ret['data'] = data
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def rename(cls, file_id, new_filename, service=None):
        try:
            ret = {}
            body = {'name':new_filename}
            svc = service if service != None else cls.service
            res = svc.files().update(fileId=file_id, body=body, fields='id,name').execute()
            ret['ret'] = 'success'
            data = {'fileid':res.get('id'), 'name':res.get('name')}
            ret['data'] = data
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def copy_file(cls, file_id, name, new_parent_id, service=None):
        try:
            ret = {}
            body = {'name':name, 'parents':[new_parent_id]}
            svc = service if service != None else cls.service
            res = svc.files().copy(fileId=file_id, body=body,
                    supportsAllDrives=True,
                    fields='id,parents').execute()
            ret['ret'] = 'success'
            data = {'folder_id':res.get('id'), 'parent_folder_id':res.get('parents')[0]}
            ret['data'] = data
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}


    @classmethod
    def search_teamdrive_by_keyword(cls, keyword, teamdrive_id, fields=None, service=None):
        try: 
            result = []
            page_token = None
            query = u'name contains "{}"'.format(keyword)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = svc.files().list(q=query, 
                            fields=str_fields,
                            corpora='drive', 
                            pageSize=100,
                            includeTeamDriveItems=True, 
                            supportsAllDrives=True, 
                            supportsTeamDrives=True, 
                            teamDriveId=teamdrive_id,
                            pageToken=page_token).execute()

                    page_token = r.get('nextPageToken', None)
                    for item in r.get('files', []): result.append(item)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('search_teamdrive_by_keyword: %d items found', len(result))
            return {'ret':'success', 'data':result}

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def search_mydrive_by_owner(cls, owner_email, mime_type='all', reverse=False, fields=None, service=None):
        try: 
            result = []
            page_token = None

            #if reverse: query = u"not '{}' in owners".format(owner_email)
            query = u"'{}' in owners".format(owner_email)
            if mime_type != 'all':
                if reverse: query = query + ' and mimeType!="{}"'.format(mime_type)
                else: query = query + ' and mimeType="{}"'.format(mime_type)
            str_fields = 'incompleteSearch, nextPageToken, files(id, name, mimeType, parents, trashed, owners, size)'
            if fields != None: str_fields = 'incompleteSearch, nextPageToken, files(' + ','.join(fields) + ')'
            svc = service if service != None else cls.sa_service
            while True:
                try:
                    """
                    r = svc.files().list(q=query, 
                            fields=str_fields,
                            corpora='user',
                            spaces='drive', 
                            pageSize=1000,
                            pageToken=page_token).execute()

                    """
                    r = svc.files().list(q=query, 
                            fields=str_fields,
                            corpora='allDrives', 
                            pageSize=100,
                            includeItemsFromAllDrives=True, 
                            includeTeamDriveItems=True, 
                            supportsAllDrives=True, 
                            pageToken=page_token).execute()
                    page_token = r.get('nextPageToken', None)
                    logger.debug(f'{r.get("files",[])},{page_token},{r.get("incompleteSearch",False)}')
                    for item in r.get('files', []): result.append(item)
                    if page_token == None: break
                    if not r.get('incompleteSearch', False): break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('search_mydrive_by_owner: %d items found', len(result))
            return {'ret':'success', 'data':result}

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}


    @classmethod
    def search_teamdrive_by_names(cls, names, teamdrive_id, mime_type='all',fields=None, service=None):
        try: 
            result = []
            page_token = None
            if len(names) > 1: query = u'name="'+u'" or name="'.join(names) + u'"'
            else: query = u'name = "{}"'.format(names[0])
            if mime_type != 'all': query = query + ' and mimeType="{}"'.format(mime_type)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = svc.files().list(q=query, 
                            fields=str_fields,
                            corpora='drive', 
                            pageSize=100,
                            includeTeamDriveItems=True, 
                            supportsAllDrives=True, 
                            supportsTeamDrives=True, 
                            teamDriveId=teamdrive_id,
                            pageToken=page_token).execute()

                    page_token = r.get('nextPageToken', None)
                    for item in r.get('files', []): result.append(item)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('search_teamdrive_by_name: %d items found', len(result))
            return {'ret':'success', 'data':result}

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def get_folder_id_by_path(cls, remote_path, service=None, teamdrive_id=None):
        try: 
            svc = service if service != None else cls.service
            parent_id = None
            if remote_path.find(':/') != -1:
                remote_name, path_str = remote_path.split(':/')
                folders = path_str.split('/')
            else:
                folders = remote_path.split('/')
            folders = list(filter(None,folders))

            root = 'root' if teamdrive_id == None else teamdrive_id
            for dname in folders:
                if parent_id == None: query = u"mimeType='application/vnd.google-apps.folder' and trashed=False and name='{}' and '{}' in parents".format(dname, root)
                else: query = u"mimeType='application/vnd.google-apps.folder' and name='{}' and trashed=False and '{}' in parents".format(dname, parent_id)

                if teamdrive_id != None:
                    r = svc.files().list(q=query, 
                            corpora='drive',
                            includeTeamDriveItems=True,
                            supportsTeamDrives=True,
                            teamDriveId=teamdrive_id).execute()
                else:
                    r = svc.files().list(q=query).execute()
                #logger.debug(r)
                logger.debug(r.get('files'))
                for item in r.get('files', []):
                    #logger.debug('getget_id:%s', item.get('id'))
                    parent_id = item.get('id')
                    break
            
            return parent_id

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def is_folder_empty(cls, target_folder_id, service=None):
        children = []
        try:
            page_token = None
            query = "'{}' in parents".format(target_folder_id)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents, trashed)'
            svc = service if service != None else cls.sa_service
            while True:
                try:
                    r = service.files().list(q=query, 
                            spaces='drive',
                            pageSize=1000,
                            fields=str_fields,
                            pageToken=page_token).execute()

                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token == None: break
                except Exception as e:
                    logger.error('Exception:%s', e)
                    logger.error(traceback.format_exc())
                    return None

            logger.debug('is_folder_empty(%s): %d items found', target_folder_id, len(children))
            if len(children) == 0: return True
            for child in children:
                if child['trashed'] == False: return False
            return True

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    @classmethod
    def get_access_token_by_remote(cls, remote):
        try:
            from google.oauth2 import service_account
            from google.oauth2.credentials import Credentials as OAuth2Credentials

            if 'token' in remote:
                expiry = datetime.strptime(remote['token']['expiry'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                if datetime.now() > expiry:
                    logger.debug('access token expired')
                    client_id = remote['client_id']
                    client_secret = remote['client_secret']
                    token = remote['token']['access_token']
                    refresh_token = remote['token']['refresh_token']
                    creds = OAuth2Credentials(token,
                            refresh_token=refresh_token,
                            id_token=None,
                            token_uri=cls.token_uri,
                            client_id=client_id,
                            client_secret=client_secret,
                            scopes=cls.scope)
                    creds.refresh(Request())
                    return creds.token
                return remote['token']['access_token']

            if 'service_account_file_path' in remote:
                path_accounts = remote['service_account_file_path']
                path_sa_json = os.path.join(path_accounts, random.choice(os.listdir(path_accounts)))
            else:
                path_sa_json = remote['service_account_file']
            logger.debug(f'selected service-account-json: {path_sa_json}')
            creds = service_account.Credentials.from_service_account_file(path_sa_json, scopes=cls.scope)
            creds.refresh(Request())
            return creds.token
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return None

    
    #########################################################
    # for changes
    @classmethod
    def get_start_token(cls, drive_id = None, service=None):
        try:
            ret = {}
            svc = service if service != None else cls.sa_service
            data = svc.changes().getStartPageToken(driveId=drive_id, supportsAllDrives=True).execute()
            ret['ret'] = 'success'
            ret['data'] = data
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret

    @classmethod
    def get_changes_by_remote(cls, remote, page_token=None, fields=None, service=None):
        try:
            ret = {}
            if service == None:
                service = cls.auth_by_rclone_remote(remote)
                if service == None:
                    logger.error('failed to auth by remote')
                    return {'ret':'exception', 'data':'failed to auth by remote'}

            drive_id = None
            if 'team_drive' in remote: drive_id = remote['team_drive'].strip()

            if page_token == None:
                r = cls.get_start_token(drive_id=drive_id, service=service)
                if r['ret'] != 'success': return ret
                page_token = r['data']['startPageToken']

            if fields == None: #default fields
                str_fields = 'nextPageToken, newStartPageToken, \
                        changes(kind, type, changeType, time, removed, fileId, \
                        file(id,md5Checksum,mimeType,modifiedTime,name,parents,teamDriveId,trashed))'
            else:
                str_fields = 'nextPageToken, newStartPageToken, \
                        changes(kind, type, changeType, time, removed, fileId, \
                        file('+','.join(fields)+'))'

            changes = []
            while page_token != None:
                res = service.changes().list(pageToken=page_token,pageSize=1000,
                        spaces='drive',driveId=drive_id,includeItemsFromAllDrives=True,
                        fields=str_fields,supportsAllDrives=True).execute()
                changes = changes + res.get('changes', [])
                #logger.debug(res)
                if 'newStartPageToken' in res:
                    new_start_token = res.get('newStartPageToken')
                    logger.debug(f'set newStartPageToken: {new_start_token}')

                page_token = res.get('nextPageToken', None)

            ret['ret'] = 'success'
            ret['data'] = {'newStartPageToken': new_start_token, 'changes':changes}
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret

    ################# NOT USE #############
    @classmethod
    def subscribe_changes(cls, page_token, callback, service=None):
        try:
            import uuid
            ret = {}
            svc = service if service != None else cls.sa_service
            body = {
                "id": str(uuid.uuid4()),
                "type": "web_hook",
                "address": callback,
                }
            data = svc.changes().watch(body=body, pageToken=page_token).execute()
            ret['ret'] = 'success'
            ret['data'] = data
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret

    @classmethod
    def subscribe_changes2(cls, remote, callback):
        try:
            import uuid
            ret = {}

            url = 'https://www.googleapis.com/drive/v3/changes/watch'
            service = cls.auth_by_rclone_remote(remote)
            resp = cls.get_start_token(service=service)
            access_token = cls.get_access_token_by_remote(remote)
            page_token = resp['data']['startPageToken']
            #data = svc.changes().list(pageToken=page_token, spaces='drive', supportsAllDrives=True).execute()
            params = {'pageToken':page_token, 'spaces':'drive', 'supportsAllDrives':True, 'includeItemsFromAllDrives':True}
            apikey = 'apikey='+SystemModelSetting.get('auth_apikey')
            logger.debug(f'{callback},{apikey},{page_token}')
            body = {
                "id": str(uuid.uuid4()),
                "type": "web_hook",
                "address": callback,
                "token": apikey,
                }
            headers = { 
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
                }

            resp = requests.post(url, headers=headers, params=params, data=json.dumps(body))
            ret['ret'] = 'success'
            ret['data'] = resp
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)
            return ret


