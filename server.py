#!/usr/bin/env python2

from __future__ import print_function

import gevent
import gevent.monkey
import gevent.wsgi
gevent.monkey.patch_all()
import sqlalchemy
import sqlalchemy.engine as sqlengine
import sqlalchemy.ext.declarative
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import Column, ForeignKey, Integer, String, Table
import falcon

import base64
import xml.etree.ElementTree as etree
import re
import traceback
import hashlib

HASH_ID_LEN = 32

Base = sqlalchemy.ext.declarative.declarative_base()

shares = Table(
    'shares', Base.metadata,
    Column('userName', String, ForeignKey('users.userName')),
    Column('projId', String(HASH_ID_LEN), ForeignKey('projects.projId'))
    )


course_teachers = Table(
    'course_teachers', Base.metadata,
    Column('teacher', String, ForeignKey('users.userName')),
    Column('course', Integer, ForeignKey('courses.courseId'))
    )


course_students = Table(
    'course_students', Base.metadata,
    Column('student', String, ForeignKey('users.userName')),
    Column('course', Integer, ForeignKey('courses.courseId'))
    )


course_assignments = Table(
    'course_assignments', Base.metadata,
    Column('course', Integer, ForeignKey('courses.courseId')),
    Column('assignment', Integer, ForeignKey('assignments.assignId'))
    )

assignment_submissions = Table(
    'assignment_submissions', Base.metadata,
    Column('assignment', Integer, ForeignKey('assignments.assignId')),
    Column('submissions', Integer, ForeignKey('submissions.submitId'))
    )

submission_members = Table(
    'submission_members', Base.metadata,
    Column('submissions', Integer, ForeignKey('submissions.submitId')),
    Column('users', String, ForeignKey('users.userName'))
    )


class User(Base):
    __tablename__ = 'users'

    userName = Column('userName', String, primary_key=True)
    password = Column('password', String)
    email = Column('email', String)
    projects = relationship('Project', secondary=shares)
    coursesTeaching = relationship('Course', secondary=course_teachers)
    coursesTaking = relationship('Course', secondary=course_students)

    def __repr__(self):
        return '<User(username={0})>'.format(self.userName)


class Revision(Base):
    __tablename__ = 'revisions'

    revId = Column('revId', String(HASH_ID_LEN), primary_key=True)
    prevId = Column('prevId', String(HASH_ID_LEN), ForeignKey('revisions.revId'))

class Project(Base):
    __tablename__ = 'projects'

    projId = Column('projId', String(HASH_ID_LEN), primary_key=True)
    ownerName = Column('ownerName', String, ForeignKey('users.userName'))
    headId = Column('headId', String(HASH_ID_LEN),
                    ForeignKey('revisions.revId'))
    members = relationship('User', secondary=shares)
    owner = relationship('User')
    #head = relationship('Revision', backref='headId')


class Course(Base):
    __tablename__ = 'courses'

    courseId = Column('courseId', String(HASH_ID_LEN), primary_key=True)
    teachers = relationship('User', secondary=course_teachers)
    students = relationship('User', secondary=course_students)
    name = Column('name', String)


class Assignment(Base):
    __tablename__ = 'assignments'

    assignId = Column('assignId', String(HASH_ID_LEN), primary_key=True)
    course = relationship('Course', secondary=course_assignments)
    name = Column('name', String)


class Submission(Base):
    __tablename__ = 'submissions'

    submitId = Column('submitId', String(HASH_ID_LEN), primary_key=True)
    assignment = relationship('Assignment', secondary=assignment_submissions)
    revisionId = Column('revisionId', String(HASH_ID_LEN), ForeignKey('revisions.revId'))
    projectId = Column('projectId', String(HASH_ID_LEN), ForeignKey('projects.projId'))
    submitterName = Column('submitterName', String, ForeignKey('users.userName'))
    #revision = relationship('Revision', backref='revisionId')
    #project = relationship('Project', backref='projectId')
    #submitter = relationship('User', backref='submitterName')
    members = relationship('User', secondary=submission_members)
    time = Column('time', sqlalchemy.DateTime)


def split_auth_token(token):
    basic, blob = token.split(' ')
    decoded = base64.b64decode(blob)
    return decoded.split(':')


def getUserPass(req):
    token = req.get_header('Authorization')
    print(req.headers)
    if token:
        return split_auth_token(token)
    else:
        return (None, None)


def requestLogin(resp):
    resp.status = falcon.HTTP_401
    resp.set_header('WWW-Authenticate', 'Basic realm="SnapServer"')


def forceUserPass(req, resp, params=None):
    username, password = getUserPass(req)
    if None in (username, password):
        requestLogin(resp)
        return None, None
    else:
        return username, password


class UsersResource(object):

    def __init__(self):
        self._users = []

    def on_get(self, req, resp, user_id=None):
        if auth(req, resp):
            resp.status = falcon.HTTP_200
            resp.body = '<user/>'


def xmlError(msg):
    return etree.tostring(etree.Element('error', attrib={'reason': msg}))


def sendError(resp, msg):
    resp.status = falcon.HTTP_500
    resp.body = xmlError(msg)


class ServerException(Exception):

    @staticmethod
    def handle(exp, req, resp, params):
        resp.status = falcon.HTTP_500
        resp.body = traceback.format_exc()
        #resp.body = xmlError(repr(exp).split('(')[0] + )


class NotAuthenticated(ServerException):
    pass


usernameRe = re.compile('[A-z0-9_.-]+')


def validUsername(username):
    return type(username) == str and usernameRe.match(username)


def xmlSuccess(element=None):
    el = etree.Element('success')
    if element is not None:
        el.append(element)
    return etree.tostring(el)


def hash_password(username, password):
    sha1 = hashlib.sha1()
    # Add the username for salting purposes
    sha1.update('SnapServer')
    sha1.update(username)
    sha1.update(password)
    sha1.update(username)
    return sha1.hexdigest()

def userExists(username):
    session = Session()
    users = session.query(User).filter(User.userName == username).all()
    return len(users) != 0


class CreateUser(object):

    def on_get(self, req, resp):
        username, password = forceUserPass(req, resp)
        if not validUsername(username):
            return sendError(resp, '{} is not a valid username.'.format(username))
        if userExists(username):
            return sendError(resp, '{} is already in use.'.format(username))
        session = Session()
        session.add(User(userName=username,
                         password=hash_password(username, password)))
        session.commit()
        resp.status = falcon.HTTP_200
        resp.body = xmlSuccess()


class ClassResource(object):

    def __init__(self):
        self._users = []

    def on_get(self, req, resp, user_id=None):
        gevent.sleep(100)
        resp.status = falcon.HTTP_200
        resp.body = '<class/>'


sql_engine = sqlengine.create_engine('sqlite:///snap.sqlite', echo=True)
sql_connection = sql_engine.connect()
Session = sessionmaker(bind=sql_engine)

Base.metadata.create_all(sql_engine)

app = falcon.API()

app.add_route('/createUser', CreateUser())

app.add_error_handler(ServerException, ServerException.handle)
app.add_error_handler(Exception, ServerException.handle)


def main():
    http = gevent.wsgi.WSGIServer(('', 5000), app)
    http.serve_forever()

if __name__ == '__main__':
    main()
