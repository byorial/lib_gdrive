# -*- coding: utf-8 -*-
# python
import os, traceback
# third-party
from flask import Blueprint
# sjva 공용
from framework.logger import get_logger
from framework import app, path_data
from framework.util import Util
from framework.common.plugin import get_model_setting, Logic
# 패키지
#########################################################
class P(object):
    package_name = __name__.split('.')[0]
    logger = get_logger(package_name)
    blueprint = menu = None

    plugin_info = {
        'version' : '0.1.0.0',
        'type' : 'library',
        'name' : package_name,
        'category_name' : 'library',
        'developer' : u'orial',
        'description' : u'gdrive api library',
        'home' : 'https://github.com/byorial/%s' % package_name,
        'more' : '',
    }
    ModelSetting = get_model_setting(package_name, logger)

    @staticmethod
    def plugin_load():
        P.logger.debug('%s plugin_load' % P.package_name)

    @staticmethod
    def plugin_unload():
        P.logger.debug('%s plugin_unload' % P.package_name)


def initialize():
    try:
        app.config['SQLALCHEMY_BINDS'][P.package_name] = 'sqlite:///%s' % (os.path.join(path_data, 'db', '{package_name}.db'.format(package_name=P.package_name)))
        from framework.util import Util
        Util.save_from_dict_to_json(P.plugin_info, os.path.join(os.path.dirname(__file__), 'info.json'))
    except Exception as e: 
        P.logger.error('Exception:%s', e)
        P.logger.error(traceback.format_exc())

initialize()
