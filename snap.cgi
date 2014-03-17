#!/usr/local/bin/python
from __future__ import print_function
activate_venv = '../bin/activate_this.py'
execfile(activate_venv, dict(__file__=activate_venv))
import wsgiref.handlers
import server

def serve():
    wsgiref.handlers.CGIHandler().run(server.app)

if __name__ == '__main__':
    serve()
