class BaseConnector(object):
    """Offline stand-in for phantom.base_connector.BaseConnector.

    The test harness drives a connector with `_shim_prepare(config, action_id)`
    then calls initialize() / handle_action(param) / finalize() itself, which
    is the same sequence the SOAR action runner uses.
    """

    def __init__(self):
        self._config = {}
        self._action_id = None
        self._results = []
        self.progress = []
        self.debug = []
        self._status = None
        self._message = ''

    # -- harness hooks -----------------------------------------------------
    def _shim_prepare(self, config=None, action_id=None):
        self._config = dict(config or {})
        self._action_id = action_id
        self._results = []
        self.progress = []
        return self

    # -- BaseConnector API used by the connector ---------------------------
    def get_config(self):
        return self._config

    def get_action_identifier(self):
        return self._action_id

    def add_action_result(self, action_result):
        self._results.append(action_result)
        return action_result

    def get_action_results(self):
        return list(self._results)

    def save_progress(self, message, *args):
        self.progress.append(message.format(*args) if args else message)

    def debug_print(self, *args):
        self.debug.append(' '.join(str(a) for a in args))

    def error_print(self, *args):
        self.debug.append('ERROR ' + ' '.join(str(a) for a in args))

    def set_status(self, status, message=''):
        self._status = status
        self._message = message or ''
        return status

    def get_status(self):
        return self._status

    def get_container_id(self):
        return 0

    def get_asset_id(self):
        return 'shim-asset'
