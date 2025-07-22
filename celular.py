#!/usr/bin/env python3
"""
CELular: The CEL-powered Linux audit utility
============================================

by circasee (https://github.com/circasee).
"""

import copy
import pwd
import re
import sys
import celpy
import json
import logging
import os
import psutil

__VERSION__ = '0.3.0-beta'


########################################################################################################################
BANNER = r"""
   ___/   \___/   \___/
 _/ ∧ \___/ ∨ \___/ ! \_
  \___/   \___/ . \___/
 _/ = \___/see\___/   \_
  \___/ca.\___/   \___/
  celular @ v{0}
""".format(__VERSION__)

basename = os.path.splitext(os.path.basename(__file__))[0]
BASECONFIG = "{}.json".format(basename)
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), BASECONFIG)
ALT_CONFIG_PATH = os.path.join('/usr/local/etc', BASECONFIG)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
_logger = logging.getLogger()
logger = _logger.getChild(basename)
logger.setLevel(logging.INFO)

ALLOWED_CHARS = re.compile('^[a-zA-Z0-9_]{1,256}$')
GLOBALS = {}
VARS = {}
CEL_ENV_OBJECTS = {}


########################################################################################################################
class Config(object):

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, path=None, _init=True):
        self.logger = logger.getChild(self.__class__.__name__)

        self.path = None
        for _path in (path, DEFAULT_CONFIG_PATH, ALT_CONFIG_PATH,):
            if os.path.isfile(_path):
                self.path = _path
                break
        
        if not self.path:
            self.logger.critical(f'Missing {BASECONFIG}')
            raise ValueError('Configuration file missing.')
        
        self.logger.info(f'config={self.path}')
        with open(self.path, 'rb') as f:
            _config = json.load(f)
        
        self._config = _config.get('config', {})
        self._spec = _config.get('spec')
        self._loggingcfg = self._config.get('logging', {})
        self._branch = _config.get('branch')
        self._options = self._config.get('options', {})
        self.version = self._config.get('version')

        _baseloglevel = self._loggingcfg.get('basename', basename)
        if _baseloglevel:
            __basenamelogger = logging.getLogger(basename)
            __basenamelogger.setLevel(self._loglevel(_baseloglevel))

        self.logger.info(f'Celular Config version {self._spec }:{self.version}-{self._branch}')

        self.globals = {}
        self.vars = {}
        self.cel_env_objects = {}
        self.expressions = {}

        if _init:
            self._parse()

    # ------------------------------------------------------------------------------------------------------------------
    def _loglevel(self, x):
        keys = ('NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        values = (0, 10, 20, 30, 40, 50)
        idx = -1
        try:
            idx = keys.index(x)
        except ValueError:
            try:
                idx = keys.index(x)
            except ValueError:
                idx = -1
        
        if idx == -1:
            return logging.INFO
        
        # Return the int value as logging.setLevel expects an int
        return values[idx]

    # ------------------------------------------------------------------------------------------------------------------
    def _parse(self, config=None):
        _config = config or self._config

        # Initialize variables
        _vars = _config.get('vars', {})
        vars = {}
        for k in _vars:
            if ALLOWED_CHARS.search(k):
                vars[k] = _vars[k]
                continue
            raise SyntaxError(f"Configuration variables must match pattern: {ALLOWED_CHARS.pattern}")
        
        #
        # Initialize Globals
        #
        # VARS = vars # accessible under "vars"-like object containing config defined variables
        _globals = _config.get('globals', {})  # accessible as global-defined named, e.g. username

        # exposes pwd module dump of users minus the pw_passwd atttribute (even though it's prob masked)
        # enabled by default due to Processes() expr's possibly using it - option is to disable it.
        #"options": {
        #    "global_common_users": false
        #},
        #if self._options.get('global_common_users', True):
        #    _users = self.get_common_users()
        #    _globals['common_users'] = list(filter(lambda x: x, map(lambda u: u.get('pw_name'), _users)))
        #    _globals['_common_users'] = list(_users)

        # Compile the global objects into CEL AST objects
        cel_env_objects = {}
        for k in _globals:
            if not ALLOWED_CHARS.search(k):
                raise SyntaxError(f"Configuration globals must match pattern: {ALLOWED_CHARS.pattern}")
            cel_env_objects[k] = celpy.json_to_cel(_globals.get(k))
        cel_env_objects.update({'vars': celpy.json_to_cel(vars)})

        # Set instance variables
        self.globals = _globals
        self.vars = vars
        self.cel_env_objects = cel_env_objects
        self.expressions = _config.get('expressions', {})


########################################################################################################################
class Expressions(object):

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, environment, expressions=[], _init=True):
        self.logger = logger.getChild(self.__class__.__name__)
        self._expressions = {}
        self._expression = {}
        self._USES_KEY = 'uses'
        self._EXPR_KEY = 'expr'
        
        self._keys = set([self._USES_KEY, self._EXPR_KEY])
        self._uses = {
            Processes.usename: Processes(),
            Mounts.usename: Mounts(),
            Users.usename: Users(),
            CommonUsers.usename: CommonUsers(),
        }

        if _init:
            if not isinstance(environment, celpy.Environment):
                raise TypeError(f'Environemnt must be instance of celpy.Environment')
            self.environment = environment
            self.load(expressions)

    # ------------------------------------------------------------------------------------------------------------------
    def load(self, expressions):
        i = 0
        for x in expressions:
            self._expressions[i] = copy.deepcopy(self._expression)
            for k in x.keys():
                if not k in self._keys:
                    raise SyntaxError(f"Expression #{i} requires keys: {self.keys}")
            for u in x.get(self._USES_KEY):
                if not u in self._uses:
                    raise SyntaxError(f"Expression #{i} has invalid use reference: {u}")
            
            expr = x.get(self._EXPR_KEY)
            
            compiled_expr = self.environment.compile(expr)
            eval_expr = self.environment.program(compiled_expr)
            self.logger.debug(f'exprno={i} rawexpr={repr(expr)}')
            self._expressions[i][self._EXPR_KEY] = eval_expr
            self._expressions[i][self._USES_KEY] = expressions[i].get(self._USES_KEY)

            i += 1

    # ------------------------------------------------------------------------------------------------------------------
    def _iter_eval(self, expressions=None, cel_env_objects=None):
        expressions = expressions or self._expressions
        cel_env_objects = cel_env_objects or CEL_ENV_OBJECTS

        for i in range(len(expressions)):
            x = expressions.get(i)
            expr = x.get(self._EXPR_KEY)
            uses = x.get(self._USES_KEY)
            self.logger.debug(f'evaluate exprno={i} uses={repr(uses)}')

            objects = CEL_ENV_OBJECTS
            for use in uses:
                raw_objs = []
                self.logger.info(f'process system data for {uses}')
                for d in self._uses.get(use, {}):
                    raw_objs.append(d)
                
                # for example, processes -> exposes the following: procs = [{pid: ..., name: ...}, ...]
                # for example, mounts -> exposes: mounts = [{device: ..., mountpoint: ...}, ...]
                objects[self._uses.get(use).objname] = celpy.json_to_cel(raw_objs)
                
                self.logger.info(f'exprno={i} use={repr(use)} objectlen={len(objects)}')

            result = expr.evaluate(objects)
            self.logger.info(f'evaluate exprno={i} result={result}') 
            yield result

    # ------------------------------------------------------------------------------------------------------------------
    def evaluate_until_one(self):
        i = 0
        for result in self._iter_eval():
            if result:
                self.logger.info(f'result={(i, True)}')
                return True
            i += 1
        self.logger.warning(f'result={("range(%d)" % i, False,)}')
        return False

    # ------------------------------------------------------------------------------------------------------------------
    def evaluate_for_each(self):
        results = []
        for result in self._iter_eval():
            results.append(bool(result))
        self.logger.info(f'results={tuple(zip(range(len(results)), results))}')
        return results


########################################################################################################################
class Mounts(object):
    usename = "mounts"
    all_keys = ['device', 'mountpoint', 'fstype', 'opts', 'maxfile', 'maxpath']

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, objname='mounts', keys=['device', 'mountpoint']):
        self.logger = logger.getChild(self.__class__.__name__)
        self.keys = keys
        self.objname = objname
        self.logger.debug(f'objname={self.objname} keys={self.keys}')

    # ------------------------------------------------------------------------------------------------------------------
    def __iter__(self):
        for _part in psutil.disk_partitions():
            # strip out any unwanted key and make sure wanted keys exits
            d = dict(filter(lambda kv: kv[0] in self.keys, _part._asdict().items()))
            for k in self.keys:
                if not k in d:
                    d[k] = None
            self.logger.debug(d)
            yield d

    # ------------------------------------------------------------------------------------------------------------------
    def to_cel(self, v):
        return {self.objname, celpy.json_to_cel(v)}

    # ------------------------------------------------------------------------------------------------------------------
    def to_json(self, all_keys=False):
        D = {}
        _keys = list(self.keys)
        keys = list(_keys)
        if all_keys:
            keys = list(self.all_keys)
        self.keys = keys

        D = {self.usename: []}
        for d in self:
            D[self.usename].append(d)
        
        return D


########################################################################################################################
class Processes(object):
    usename = "processes"
    all_keys = ['cmdline', 'connections', 'cpu_affinity', 'cpu_num', 
                'cpu_percent', 'cpu_times', 'create_time', 'cwd', 
                'environ', 'exe', 'gids', 'io_counters', 'ionice', 
                'memory_full_info', 'memory_info', 'memory_maps', 
                'memory_percent', 'name', 'nice', 'num_ctx_switches', 
                'num_fds', 'num_handles', 'num_threads', 'open_files', 
                'pid', 'ppid', 'status', 'terminal', 'threads', 
                'uids', 'username']

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, objname="procs", keys=['pid', 'name', 'exe', 
                                              'username', 'cwd', 
                                              'create_time', 'open_files']):
        self.logger = logger.getChild(self.__class__.__name__)
        self.keys = keys
        self._process_iter_attrs = keys
        self.objname = objname
        self.logger.debug(f'objname={self.objname} keys={self.keys}')

    # ------------------------------------------------------------------------------------------------------------------
    def __iter__(self):
        for _proc in psutil.process_iter(self._process_iter_attrs):
            # strip out any unwanted key and make sure wanted keys exits
            d = dict(
                filter(lambda kv: kv[0] in self.keys, _proc.as_dict().items())
            )
            # add any missing keys to the dict
            for k in self.keys:
                if not k in d:
                    d[k] = None
            self.logger.debug(d)
            yield d

    # ------------------------------------------------------------------------------------------------------------------
    def to_cel(self, v):
        return {self.objname, celpy.json_to_cel(v)}

    # ------------------------------------------------------------------------------------------------------------------
    def to_json(self, all_keys=False):
        D = {}
        _keys = list(self.keys)
        keys = list(_keys)
        if all_keys:
            # https://psutil.readthedocs.io/en/latest/#psutil.process_iter
            # psutil.process_iter() will throw an exception if attr names specified
            # are not in the process information. Setting the self.keys to an empty
            # list causes the psutil.process_iter() method to complete but because
            # self.keys() is used to filter the results and ensure keys exist, an
            # empty list() thus results in no values! the result is an empty JSON
            # set of output data. For example:
            # {"processes": {"processes": [{}, {}, {}, ..., {}], }, "mounts": {...
            #
            # As such, a new field is specified as self._process_iter_attrs 
            # in order to account for this nuance in the code and psutil.process_iter().
            #
            # Empty list returns all values; otherwise throws an exception, e.g.
            #     ValueError: invalid attr names 'num_handles', 'connections'
            self.keys = list(self.all_keys)
            self._process_iter_attrs = []

        self.keys = keys

        D = {self.usename: []}
        for d in self:
            D[self.usename].append(d)
        
        return D


########################################################################################################################
class Users(object):
    usename = "users"
    all_keys = ['pw_name', 'pw_passwd', 'pw_uid', 'pw_gid', 
                'pw_gecos', 'pw_dir', 'pw_shell']

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, objname="users", keys=['pw_name', 'pw_uid', 
                                              'pw_gid', 'pw_gecos', 
                                              'pw_dir', 'pw_shell']):
        self.logger = logger.getChild(self.__class__.__name__)
        self.keys = keys
        self.objname = objname
        self.logger.debug(f'objname={self.objname} keys={self.keys}')

    # ------------------------------------------------------------------------------------------------------------------
    def __iter__(self):
        for u in self._get_users():
            d = {}
            for k in self.keys:
                d[k] = u.get(k, None)
            yield d
            self.logger.debug(d)

    # ------------------------------------------------------------------------------------------------------------------
    def _get_users(self, _attrs=['pw_name', 'pw_passwd', 'pw_uid', 'pw_gid', 'pw_gecos', 'pw_dir', 'pw_shell']):
        users = []
        for user in filter(lambda u: u, pwd.getpwall()):
            u = {}
            for attr in filter(lambda a: a != 'pw_passwd', _attrs):
                u[attr] = getattr(user, attr)
            users.append(dict(u))
        return users

    # ------------------------------------------------------------------------------------------------------------------
    def to_json(self, all_keys=False):
        D = {}
        _keys = list(self.keys)
        keys = list(_keys)
        if all_keys:
            keys = list(self.all_keys)
        self.keys = keys

        D = {self.usename: []}
        for d in self:
            D[self.usename].append(d)
        
        self.keys = list(_keys)

        return D


########################################################################################################################
class CommonUsers(Users):
    usename = "common_users"
    all_keys = []

    # ------------------------------------------------------------------------------------------------------------------
    def __init__(self, objname="common_users", keys=['pw_name', 'pw_uid', 'pw_gid', 
                                                     'pw_gecos', 'pw_dir', 'pw_shell'], *args, **kwargs):
        self.logger = logger.getChild(self.__class__.__name__)
        super().__init__(self, *args, **kwargs)
        self.keys = keys
        self.objname = objname
        self.logger.debug(f'objname={self.objname} keys={self.keys}')

    # ------------------------------------------------------------------------------------------------------------------
    def __iter__(self):
        for user in self._get_users():
            yield user

    # ------------------------------------------------------------------------------------------------------------------
    def _get_users(self, _uid_min=1000, _uid_max=1999, _attrs=['pw_name', 'pw_passwd', 
                                                               'pw_uid', 'pw_gid', 'pw_gecos', 'pw_dir', 'pw_shell']):
        users = set()
        for user in filter(lambda u: u.get('pw_uid') >= _uid_min and u.get('pw_uid') <= _uid_max, super()._get_users()):
            users.add(user.get('pw_name'))
        return list(users)

    # ------------------------------------------------------------------------------------------------------------------
    def to_json(self, *args, **kwargs):
        return self._get_users()


########################################################################################################################
def to_json(uses=[], all_keys=False):
    e = Expressions(environment=None, _init=False)
    D = {}
    if not uses:
        uses.extend(e._uses.keys())
    
    for k in filter(lambda u: u in uses, e._uses):
        obj = e._uses.get(k)
        val = obj.to_json(all_keys)
        if isinstance(val, dict):
            D[k] = val
        elif isinstance(val, list):
            D[k] = {obj.usename: val}
    return json.dumps(D)


########################################################################################################################
def service(config):
    system_in_use = True
    try:
        CEL_ENV = celpy.Environment()
        check_expressions = Expressions(CEL_ENV, config.expressions)
        #print(check_expressions.evaluate_until_one())  # e.g. True
        results = check_expressions.evaluate_for_each()
        system_in_use = any(results)
        #print(results)  # e.g. [True, True, True, True]
    except Exception as E:
        print(repr(E), file=sys.stderr)
        system_in_use = True
    return int(system_in_use)


########################################################################################################################
def main(argv):
    global GLOBALS, VARS, CEL_ENV_OBJECTS

    uses = list(Expressions(environment=None, _init=False)._uses.keys())
    opt_config_file = None
    opt_json_output = False
    opt_json_output_all = False
    opt_uses = set()
    usage_str = f'{basename} [--json-output[={"][,".join(uses)}] [--json-output-all] [--config=/path/to/config.json]'

    for arg in argv:
        argl = arg.lower()
        if argl.startswith('--json-output='):
            _arg, _sep, _val = arg.partition('=')
            for v in _val.split(','):
                if not v in uses:
                    print(f'Unknown use: {repr(v)}', file=sys.stderr)
                    return -1
                opt_uses.add(v)
        if argl == '--json-output':
            opt_uses = set(uses)
        if argl == '--json-output-all':
            opt_json_output_all = True
        if argl.startswith('--config='):
            _arg, _sep, _val = arg.partition('=')
            _path = os.path.abspath(_val)
            if not os.path.isfile(_path):
                print(f'Unknown file: {repr(_path)}', file=sys.stderr)
                return -1
            opt_config_file = _path
        if argl == '--help':
            print(BANNER)
            print(usage_str)
            return -1
    
    opt_config_file = opt_config_file or DEFAULT_CONFIG_PATH
    config = Config(opt_config_file)
    
    GLOBALS, VARS, CEL_ENV_OBJECTS = config.globals, config.vars, config.cel_env_objects

    opt_json_output = any(opt_uses) or opt_json_output_all
    if opt_json_output:
        print(to_json(uses=list(opt_uses), all_keys=opt_json_output_all))
        return 0
    
    exit_code = service(config)
    return exit_code


########################################################################################################################
########################################################################################################################
if __name__ == '__main__':
    __DEBUG = 0
    # Any non-zero return code means the system is in use
    # Non-zero will cause dependent shell scripts to fail
    #
    # A zero return code means it is not in use
    # Zero will allow shell scripts to continue
    #
    if __DEBUG:
        sys.exit(main(sys.argv) or 411)
    try:
        ret = main(sys.argv)
        # epilog()
    except:
        # Cause dependent actions to fail, e.g. fail-safe, don't reboot
        ret = 911
    sys.exit(ret)
