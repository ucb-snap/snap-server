#!/usr/bin/env python2

from __future__ import print_function
from werkzeug.serving import run_with_reloader
import gevent.wsgi

def main():
    import server
    http = gevent.wsgi.WSGIServer(('', 5000), server.app)
    http.serve_forever()

if __name__ == '__main__':
    run_with_reloader(main, 'server.py')
