
import random
import string

import radiusd


# defining function for random
# string id with parameter
def idgen(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))


class Logger(object):
    def __init__(self, module):
        self._module = module

    def critical(self, msg):
        self.error(msg)

    def error(self, msg):
        msg = str(msg).split('\n')
        if len(msg) > 1:
            lid = idgen(5)
            for line in msg:
                radiusd.radlog(radiusd.L_ERR,
                               'calabiyau [%s] (ERROR): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_ERR,
                           'calabiyau (ERROR): %s' % (msg[0],))

    def debug(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_DBG,
                               'calabiyau [%s] (DEBUG): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_DBG,
                           'calabiyau (DEBUG): %s' % (msg[0],))

    def info(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_INFO,
                               'calabiyau [%s] (INFO): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_INFO,
                           'calabiyau (INFO): %s' % (msg[0],))

    def warning(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_INFO,
                               'calabiyau [%s] (WARNING): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_INFO,
                           'calabiyau (WARNING): %s' % (msg[0],))

    def auth(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_AUTH,
                               'calabiyau [%s] (AUTH): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_AUTH,
                           'calabiyau (AUTH): %s' % (msg[0],))
