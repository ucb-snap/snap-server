#!/usr/bin/env python2

from __future__ import print_function

import gevent
import gevent.monkey
import gevent.wsgi
gevent.monkey.patch_all()
import sqlalchemy
import sqlalchemy.engine as sqlengine
import sqlalchemy.ext.declarative
from sqlalchemy.orm import relationship, sessionmaker, join
from sqlalchemy import Column, ForeignKey, Integer, String, Table, Boolean
import falcon

import base64
import xml.etree.ElementTree as etree
import xml.dom.minidom as mdom
import re
import traceback
import hashlib
import random

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

    userName = Column(String, primary_key=True)
    password = Column(String)
    email = Column(String)
    projects = relationship('Project', secondary=shares)
    coursesTeaching = relationship('Course', secondary=course_teachers)
    coursesTaking = relationship('Course', secondary=course_students)

    def toXMLName(self):
        return Elt('user', {'userName': self.userName})


class Revision(Base):
    __tablename__ = 'revisions'

    revId = Column(String(HASH_ID_LEN), primary_key=True)
    prevId = Column(String(HASH_ID_LEN),
                    ForeignKey('revisions.revId'))


def Elt(tag, attrib=None, text='', children=()):
    elt = mdom.Element(tag)
    if attrib is not None:
        for k, v in attrib.items():
            elt.setAttribute(k, v)
    if text:
        elt.appendChild(mdom.Text())
        elt.firstChild.replaceWholeText(text)
    for child in children:
        elt.appendChild(child)
    return elt


def printXML(elt):
    return elt.toprettyxml()


class Project(Base):
    __tablename__ = 'projects'

    projId = Column(String(HASH_ID_LEN), primary_key=True)
    ownerName = Column(String, ForeignKey('users.userName'))
    headId = Column(String(HASH_ID_LEN), ForeignKey('revisions.revId'))
    members = relationship('User', secondary=shares)
    owner = relationship('User')
    head = relationship('Revision')
    public = Column(Boolean)

    def toXML(self):
        proj = Elt('project')
        proj.appendChild(Elt('projId', text=self.projId))
        proj.appendChild(Elt('owner', children=[self.owner.toXMLName()]))
        members = Elt('members')
        for mem in self.members:
            members.appendChild(mem.toXMLName())
        proj.appendChild(members)
        return proj


class Course(Base):
    __tablename__ = 'courses'

    courseId = Column(String(HASH_ID_LEN), primary_key=True)
    teachers = relationship('User', secondary=course_teachers)
    students = relationship('User', secondary=course_students)
    name = Column(String)


class Assignment(Base):
    __tablename__ = 'assignments'

    assignId = Column(String(HASH_ID_LEN), primary_key=True)
    course = relationship('Course', secondary=course_assignments)
    name = Column('name', String)


class Submission(Base):
    __tablename__ = 'submissions'

    submitId = Column(String(HASH_ID_LEN), primary_key=True)
    assignment = relationship('Assignment', secondary=assignment_submissions)
    revisionId = Column(String(HASH_ID_LEN), ForeignKey('revisions.revId'))
    projectId = Column(String(HASH_ID_LEN), ForeignKey('projects.projId'))
    submitterName = Column(String, ForeignKey('users.userName'))
    revision = relationship('Revision')
    project = relationship('Project')
    submitter = relationship('User')
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


def xmlError(msg):
    return printXML(Elt('error', attrib={'reason': msg}))


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


class IncorrectPassword(ServerException):
    pass


class NoSuchUser(ServerException):
    pass


usernameRe = re.compile('[A-z0-9_.-]+')


def validUsername(username):
    return type(username) == str and usernameRe.match(username)


def xmlSuccess(*args, **kwargs):
    return printXML(Elt('success', *args, **kwargs))


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
    res = session.query(User).filter(User.userName == username).count() != 0
    session.rollback()
    return res


def auth(session, req, resp):
    username, password = forceUserPass(req, resp)
    if None in (username, password):
        return None
    users = session.query(User).filter(User.userName == username).all()
    if len(users) == 0:
        raise NoSuchUser()
    user = users[0]
    if hash_password(username, password) != user.password:
        raise IncorrectPassword()
    else:
        return user


class CreateUser(object):

    def on_get(self, req, resp):
        username, password = forceUserPass(req, resp)
        if not validUsername(username):
            return sendError(resp,
                             '{} is not a valid username.'.format(username))
        if userExists(username):
            return sendError(resp, '{} is already in use.'.format(username))
        session = Session()
        session.add(User(userName=username,
                         password=hash_password(username, password)))
        session.commit()
        resp.status = falcon.HTTP_200
        resp.body = xmlSuccess()


def generateProjId():
    return format(random.randint(0, 2**128), 'x')


class CreateProject(object):

    def on_get(self, req, resp):
        session = Session()
        user = auth(session, req, resp)
        if user is None:
            return
        projId = generateProjId()
        proj = Project(projId=projId, owner=user)
        proj.members.append(user)
        session.add(proj)
        session.commit()
        resp.status = falcon.HTTP_200
        el = Elt('success', {'projId': projId})
        resp.body = printXML(el)


class ListProjects(object):

    def on_get(self, req, resp):
        session = Session()
        user = auth(session, req, resp)
        if user is None:
            return
        projects = session.query(Project) \
                          .filter(Project.members.contains(user)) \
                          .all()
        success = Elt('success')
        for proj in projects:
            success.appendChild(proj.toXML())
        session.rollback()
        resp.status = falcon.HTTP_200
        resp.body = printXML(success)


sql_engine = sqlengine.create_engine('sqlite:///snap.sqlite', echo=False)
sql_connection = sql_engine.connect()
Session = sessionmaker(bind=sql_engine)

Base.metadata.create_all(sql_engine)

app = falcon.API()

app.add_route('/createUser', CreateUser())
app.add_route('/createProject', CreateProject())
app.add_route('/listProjects', ListProjects())

app.add_error_handler(ServerException, ServerException.handle)
app.add_error_handler(Exception, ServerException.handle)


def main():
    http = gevent.wsgi.WSGIServer(('', 5000), app)
    http.serve_forever()

if __name__ == '__main__':
    main()
