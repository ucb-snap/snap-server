#!/usr/local/bin/python
from __future__ import print_function
activate_venv = '../bin/activate_this.py'
execfile(activate_venv, dict(__file__=activate_venv))
import wsgiref.handlers
import server

def serve():
    try:
        import os
        if os.environ['REQUEST_URI'].endswith('snap.cgi'):
            print('Content-Type: application/xml; charset=utf-8')
            print()
            print(server.xmlError('Could not parse url.'))
        else:
            wsgiref.handlers.CGIHandler().run(server.app)
    except Exception as e:
        print('Content-Type: application/xml; charset=utf-8')
        print()
        print(server.xmlError('Internal server error.'))

if __name__ == '__main__':
    serve()
