class ActionResult(object):
    """Offline stand-in for phantom.action_result.ActionResult."""

    def __init__(self, param=None):
        self._param = dict(param or {})
        self._data = []
        self._summary = {}
        self._status = None
        self._message = ''

    def add_data(self, item):
        self._data.append(item)

    def update_summary(self, summary):
        self._summary.update(summary)
        return self._summary

    def set_status(self, status, message=''):
        self._status = status
        self._message = message or ''
        return status

    def get_status(self):
        return self._status

    def get_message(self):
        return self._message

    def get_data(self):
        return self._data

    def get_summary(self):
        return self._summary

    def get_param(self):
        return self._param
