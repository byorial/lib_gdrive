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
    os.system("{} install oauth2client".format(app.config['config']['pip']))
    from oauth2client.service_account import ServiceAccountCredentials

try:
    from googleapiclient.discovery import build
except ImportError:
    os.system("{} install googleapiclient".format(app.config['config']['pip']))
    from googleapiclient.discovery import build

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
    def sa_authorize(cls, json_path, return_service=False):
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

        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, cls.scope)
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
            if service != None:
                shortcut = service.files().create(body=shortcut_metadata, 
                        fields='id,shortcutDetails').execute()
            else:
                shortcut = cls.sa_service.files().create(body=shortcut_metadata, 
                        fields='id,shortcutDetails').execute()

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
            str_fields = 'id, name, mimeType, parents'
            if fields != None: str_fields = ",".join(fields)
            if service != None: info = service.files().get(fileId=folder_id, fields=str_fields).execute()
            else: info = cls.sa_service.files().get(fileId=folder_id, fields=str_fields).execute()
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


    @classmethod
    def get_gdrive_full_path(cls, folder_id, service=None):
        try:
            pathes = []
            parent_id = folder_id
            while True:
                if service != None:
                    r = service.files().get(fileId=parent_id, 
                            fields='id, name, mimeType, parents').execute()
                else:
                    r = cls.sa_service.files().get(fileId=parent_id, 
                            fields='id, name, mimeType, parents').execute()

                if 'parents' in r:
                    parent_id = r['parents'][0]
                    pathes.append(r['name'])
                else:
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
            while True:
                if service != None:
                    r = service.files().get(fileId=parent_id, fields='id, name, mimeType, parents').execute()
                else:
                    r = cls.sa_service.files().get(fileId=parent_id, fields='id, name, mimeType, parents').execute()
                if 'parents' in r:
                    logger.debug('fodler_id: %s, parent_id: %s', folder_id, parent_id)
                    parent_id = r['parents'][0]
                    if parent_id != folder_id:
                        pathes.append(r['name'])
                else:
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
    
            while True:
                if service != None:
                    r = service.files().list(q=query,
                            spaces='drive',
                            pageSize=1000,
                            fields='nextPageToken, files(id, name, parents, modifiedTime)',
                            pageToken=page_token).execute()
                else:
                    r = cls.sa_service.files().list(q=query,
                            spaces='drive',
                            pageSize=1000,
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
    def get_children(cls, target_folder_id, fields=None, service=None, time_after=None):
        children = []
        try:
            page_token = None
            if time_after == None:
                query = "'{}' in parents".format(target_folder_id)
            else:
                query = "modifiedTime >= '{}' and '{}' in parents".format(cls.get_gdrive_time_str(_datetime=time_after), target_folder_id)
            str_fields = 'nextPageToken, files(id, name, mimeType, parents)'
            if fields != None: str_fields = 'nextPageToken, files(' + ','.join(fields) + ')'
            while True:
                try:
                    if service != None:
                        r = service.files().list(q=query, 
                                spaces='drive',
                                pageSize=1000,
                                fields=str_fields,
                                pageToken=page_token).execute()
                    else:
                        r = cls.sa_service.files().list(q=query, 
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

            while True:
                try:
                    if service != None:
                        r = service.files().list(q=query, 
                                spaces='drive',
                                pageSize=1000,
                                fields='nextPageToken, files(id, name, parents, mimeType)',
                                pageToken=page_token).execute()
                    else:
                        r = cls.sa_service.files().list(q=query, 
                                spaces='drive',
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
    
            logger.debug('get_children_folders(%s): %d items found', target_folder_id, len(children))
            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def get_children_folders_with_parents(cls, parents, service=None):
        children = []
        try:
            page_token = None
            parents_str = " in parents or ".join(["'"+x+"'" for x in parents]) + " in parents"
            query = "mimeType='application/vnd.google-apps.folder' and ({})".format(parents_str)
            logger.debug(query)

            while True:
                try:
                    if service != None:
                        r = service.files().list(q=query, 
                                spaces='drive',
                                corpora='allDrives',
                                includeItemsFromAllDrives=True,
                                pageSize=1000,
                                fields='nextPageToken, files(id, name, parents, mimeType)',
                                pageToken=page_token).execute()
                    else:
                        r = cls.sa_service.files().list(q=query, 
                                spaces='drive',
                                corpora='allDrives',
                                includeItemsFromAllDrives=True,
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
    def get_gdrive_time_str(cls, _datetime = None, _delta_min = None):
        if _datetime == None: _date_time = datetime.now()
        if _delta_min == None: _delta_min = 0
        tt  = _datetime - timedelta(minutes=_delta_min)
        return tt.strftime('%Y-%m-%dT%H:%M:%S+09:00')

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

            while True:
                try:
                    if service != None:
                        r = service.files().list(q=query, 
                                spaces='drive',
                                pageSize=1000,
                                fields='nextPageToken, files(id, name, parents, mimeType)',
                                pageToken=page_token).execute()
                    else:
                        r = cls.sa_service.files().list(q=query, 
                                spaces='drive',
                                pageSize=1000,
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
    def create_sub_folder(cls, name, parent_folder_id):
        try:
            ret = {}
            parent_id = parent_folder_id
            meta = {'name': name, 'mimeType': 'application/vnd.google-apps.folder', 'parents': [parent_id]}
            newfolder = cls.service.files().create(body=meta, fields='id').execute()
            data = {'name':name, 'folder_id':newfolder.get('id'), 'parent_folder_id':parent_id}
            ret['ret'] = 'success'
            ret['data'] = data
            return ret

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error', 'msg':str(e)}

    @classmethod
    def delete_file(cls, file_id):
        try:
            ret = {}
            data = []
            cls.service.files().delete(fileId=file_id).execute()
            ret['ret'] = 'success'
            return ret
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
            return {'ret':'error:{}'.format(str(e))}

    @classmethod
    def move_file(cls, file_id, old_parent_id, new_parent_id):
        try:
            ret = {}
            res = cls.service.files().update(fileId=file_id, 
                    addParents=new_parent_id, 
                    removeParents=old_parent_id, 
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

            while True:
                try:
                    if service != None:
                        r = service.files().list(q=query, 
                                fields=str_fields,
                                corpora='drive', 
                                pageSize=100,
                                includeTeamDriveItems=True, 
                                supportsAllDrives=True, 
                                supportsTeamDrives=True, 
                                teamDriveId=teamdrive_id,
                                pageToken=page_token).execute()
                    else:
                        r = cls.sa_service.files().list(q=query, 
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
