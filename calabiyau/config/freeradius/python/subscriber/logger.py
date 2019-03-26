
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
                               'subscriber [%s] (ERROR): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_ERR,
                           'subscriber (ERROR): %s' % (msg[0],))

    def debug(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_DBG,
                               'subscriber [%s] (DEBUG): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_DBG,
                           'subscriber (DEBUG): %s' % (msg[0],))

    def info(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_INFO,
                               'subscriber [%s] (INFO): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_INFO,
                           'subscriber (INFO): %s' % (msg[0],))

    def warning(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_INFO,
                               'subscriber [%s] (WARNING): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_INFO,
                           'subscriber (WARNING): %s' % (msg[0],))

    def auth(self, msg):
        msg = str(msg).split('\n')
        lid = idgen(5)
        if len(msg) > 1:
            for line in msg:
                radiusd.radlog(radiusd.L_AUTH,
                               'subscriber [%s] (AUTH): %s' % (lid, line,))
        else:
            radiusd.radlog(radiusd.L_AUTH,
                           'subscriber (AUTH): %s' % (msg[0],))
