# -*- coding: utf-8 -*-
#########################################################
# python
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
except:
    os.system("{} install oauth2client".format(app.config['config']['pip']))
    from oauth2client.service_account import ServiceAccountCredentials

try:
    from googleapiclient.discovery import build
except:
    os.system("{} install googleapiclient".format(app.config['config']['pip']))
    from googleapiclient.discovery import build

# anytree
try:
    from anytree import Node, PreOrderIter
except:
    os.system("{} install anytree".format(app.config['config']['pip']))
    from anytree import Node, PreOrderIter

# 패키지
from .plugin import P
logger = P.logger


#########################################################

class LibGdrive(object):
    service     = None
    json_list   = []

    @classmethod
    def authorize(cls, json_path):
        if not os.path.exists(json_path):
            logger.error('can not recognize gdrive_auth_path(%s)', json_path)
            data = {'type':'warning', 'msg':'인증파일(.json) 경로를 확인해주세요.'}
            socketio.emit('notify', data, namespace='/framework', broadcast=True)
            return

        if os.path.isdir(json_path):
            cls.json_list = cls.get_all_jsonfiles(json_path)
            logger.debug('load json list(%d)', len(cls.json_list))
            json_file = ''.join(random.sample(cls.json_list, 1))
        else:
            json_file = json_path
            cls.json_list = [json_path]

        logger.debug('json_file: %s', json_file)

        scope = ['https://www.googleapis.com/auth/drive']
        try:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, scope)
            cls.service = build('drive', 'v3', credentials=credentials)
        except Exception as e: 
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def switch_service_account(cls):
        while True:
            try:
                scope = ['https://www.googleapis.com/auth/drive']
                json_file = ''.join(random.sample(cls.json_list, 1))
                credentials = ServiceAccountCredentials.from_json_keyfile_name(json_file, scope)
                cls.service = build('drive', 'v3', credentials=credentials)
                return cls.service
            except Exception as e: 
                logger.error('Exception:%s', e)
                logger.error(traceback.format_exc())
                if len(cls.json_list) == 1: return None

    @classmethod
    def create_shortcut(cls, shortcut_name, target_folder_id, parent_folder_id):
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
            shortcut = cls.service.files().create(body=shortcut_metadata, 
                    fields='id,shortcutDetails').execute()

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
    def get_file_info(cls, folder_id):
        try:
            ret = {}
            info = cls.service.files().get(fileId=folder_id, fields='id, name, mimeType, parents').execute()
            data = {'id':info['id'], 'mimeType':info['mimeType'], 'name':info['name'], 'parent':info['parents'][0]}
            ret['ret'] = 'success'
            ret['data'] = data
            return ret
        except Exception as e:
            logger.debug('Exception:%s', e)
            logger.debug(traceback.format_exc())
            ret['ret'] = 'exception'
            ret['data'] = str(e)


    @classmethod
    def get_gdrive_full_path(cls, folder_id):
        pathes = []
        parent_id = folder_id
        while True:
            r = cls.service.files().get(fileId=parent_id, fields='id, name, mimeType, parents').execute()
            if 'parents' in r:
                parent_id = r['parents'][0]
                pathes.append(r['name'])
            else:
                pathes.append(r['name'])
                break

        pathes.append('')
        pathes.reverse()
        return u'/'.join(pathes)

    @classmethod
    def get_all_folders_in_folder(cls, root_folder_id, last_searched_time):
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
            response = cls.service.files().list(q=query,
                    spaces='drive',
                    pageSize=1000,
                    fields='nextPageToken, files(id, name, parents, modifiedTime)',
                    pageToken=page_token).execute()
    
            folders = response.get('files', [])
            page_token = response.get('nextPageToken', None)

            for folder in folders:
                child_folders[folder['id']] = folder['parents'][0]
            if page_token is None: break
    
        return child_folders

    @classmethod
    def get_subfolders_of_folder(cls, folder_to_search, all_folders):
        temp_list = [k for k, v in all_folders.items() if v == folder_to_search]
        for sub_folder in temp_list:
            yield sub_folder
            for x in cls.get_subfolders_of_folder(sub_folder, all_folders):
                yield x

    @classmethod
    def get_all_folders(cls, root_folder_id, last_searched_time):
        all_folders = cls, LogicGdrive.get_all_folders_in_folder(root_folder_id, last_searched_time)
        target_folder_list = []
        for folder in LogicGdrive.get_subfolders_of_folder(root_folder_id, all_folders):
            target_folder_list.append(folder)
        return target_folder_list

    @classmethod
    def get_children_folders(cls, target_folder_id):
        children = []
        try:
            page_token = None
            query = "mimeType='application/vnd.google-apps.folder'\
                    and '{}' in parents".format(target_folder_id)

            while True:
                try:
                    r = cls.service.files().list(q=query, 
                            spaces='drive',
                            pageSize=1000,
                            fields='nextPageToken, files(id, name, parents, mimeType)',
                            pageToken=page_token).execute()
                
                    page_token = r.get('nextPageToken', None)
                    for child in r.get('files', []): children.append(child)
                    if page_token is None: break
                except:
                    cls.service = LogicGdrive.switch_service_account()
                    if cls.service == None:
                        return None

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
    def get_children_video_files(cls, parent_folder_id, time_after=None):
        children = []
        try:
            page_token = None
            if time_after == None:
                query = "mimeType contains 'video/' and '{}' in parents".format(parent_folder_id)
            else:
                query = "mimeType contains 'video/'\
                        and '{}' in parents\
                        and modifiedDate >= {}".format(parent_folder_id, cls.get_gdrive_time_str(_datetime=time_after))

            while True:
                try:
                    r = cls.service.files().list(q=query, 
                            spaces='drive',
                            pageSize=1000,
                            fields='nextPageToken, files(id, name, parents, mimeType)',
                            pageToken=page_token).execute()
                
                    logger.debug(json.dumps(r, indent=2))
                    for child in r.get('files', []): children.append(child)
                    page_token = r.get('nextPageToken', None)
                    if page_token == None: break
                except:
                    cls.service = cls.switch_service_account()
                    if cls.service == None:
                        return None

            return children

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def populate_tree(cls, parent, parent_id, depth):
        try:
            children = cls.get_children_folders(parent_id)
            children_nodes = []
            if len(children) > 0:
                for child in children:
                    node = Node(child['name'], parent=parent, id=child['id'], parent_id=parent_id, mime_type=child['mimeType'])
                    children_nodes.append(node)
                    logger.debug('add-tree:{},{},{}'.format(node.name, node.parent_id, node.id))

            if depth-1 == 0: return
            for node in children_nodes:
                LogicGdrive.populate_tree(node, node.id, depth-1)

        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())

    @classmethod
    def get_all_subfolders(cls, root_folder_id, name=None, max_depth=1):
        try:
            if name == None: name = cls.get_file_info(root_folder_id)['name']
            root = Node(name, id=root_folder_id)
            cls.populate_tree(root, root_folder_id, max_depth)

            folder_list = []
            for node in PreOrderIter(root, filter_=lambda n:n.height == 0):
                folder = {}
                folder['name'] = node.name
                folder['folder_id'] = node.id
                folder['parent_folder_id'] = node.parent_id
                folder['mime_type'] = node.mime_type
                folder_list.append(folder)

            return folder_list
        except Exception as e:
            logger.error('Exception:%s', e)
            logger.error(traceback.format_exc())
