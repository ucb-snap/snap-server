#!/usr/bin/env python2

from __future__ import print_function

import gevent
import gevent.monkey
import gevent.wsgi
import gevent.fileobject
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
import os
import os.path

HASH_ID_LEN = 40
STORAGE_DIR = 'storage'

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

    def filename(self):
        return os.path.join(STORAGE_DIR, self.revId + '.revision')

    def save(self, contents):
        f = gevent.fileobject.FileObjectThread(open(self.filename(), 'w'))
        f.write(contents)

    def load(self):
        f = gevent.fileobject.FileObjectThread(open(self.filename()))
        return f.read()


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


def formatXML(elt):
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
    return formatXML(Elt('error', attrib={'reason': msg}))


def sendError(resp, msg):
    resp.status = falcon.HTTP_500
    resp.body = xmlError(msg)


def handle_exception(exp, req, resp, params):
    resp.status = falcon.HTTP_500
    resp.body = xmlError(traceback.format_exc())


class ServerException(Exception):

    @staticmethod
    def handle_callback(exp, req, resp, params):
        return exp.handle(req, resp, params)

    def handle(self, req, resp, params):
        handle_exception(req, resp, params)


class NotAuthenticated(ServerException):
    pass


class NeedAuthentication(ServerException):

    def handle(self, req, resp, params):
        requestLogin(resp)
        resp.body = xmlError('Need authentication')


class IncorrectPassword(ServerException):

    def handle(self, req, resp, params):
        requestLogin(resp)
        resp.body = xmlError('Incorrect password')


class NoSuchUser(ServerException):
    pass


class NoSuchProject(ServerException):
    pass


class MissingParameter(ServerException):

    def __init__(self, param):
        self._param = param
        ServerException.__init__(self)

    def handle(self, req, resp, params):
        resp.status = falcon.HTTP_400
        resp.body = xmlError('Missing parameter {}.'.format(self._param))


usernameRe = re.compile('[A-z0-9_.-]+')


def validUsername(username):
    return type(username) == str and usernameRe.match(username)


def xmlSuccess(*args, **kwargs):
    return formatXML(Elt('success', *args, **kwargs))


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
        raise NeedAuthentication()
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


def formatHash(hsh):
    return format(hsh, '0{}x'.format(HASH_ID_LEN))


def generateHashId():
    return formatHash(random.randrange(0, 2**160))


def generateProjId():
    return generateHashId()


def generateCourseId():
    return generateHashId()


class CreateProject(object):

    def on_get(self, req, resp):
        session = Session()
        user = auth(session, req, resp)
        projId = generateProjId()
        proj = Project(projId=projId, owner=user)
        proj.members.append(user)
        session.add(proj)
        session.commit()
        resp.status = falcon.HTTP_200
        el = Elt('success', {'projId': projId})
        resp.body = formatXML(el)


def forceParam(req, paramName):
    param = req.get_param(paramName)
    if param is None:
        raise MissingParameter(paramName)
    else:
        return param


def get_or_create(session, model, defaults=None, *args, **kwargs):
    instance = session.query(model).filter_by(*args, **kwargs).first()
    if instance is not None:
        return instance, False
    else:
        params = dict((k, v) for k, v in kwargs.iteritems() if not
                      isinstance(v, sqlalchemy.sql.ClauseElement))
        if defaults is not None:
            params.update(defaults)
        instance = model(**params)
        session.add(instance)
        return instance, True


class SaveProject(object):

    def on_post(self, req, resp):
        session = Session()
        user = auth(session, req, resp)
        projId = forceParam(req, 'projId')
        projects = session.query(Project) \
                          .filter(Project.projId == projId) \
                          .all()
        if len(projects) == 0:
            raise NoSuchProject()
        project = projects[0]
        contents = req.stream.read()
        prevId = formatHash(0)
        if project.head is not None:
            prevId = project.head.revId
        sha1 = hashlib.sha1()
        sha1.update(prevId)
        sha1.update(contents)
        revId = sha1.hexdigest()
        revision, created = get_or_create(session, Revision, revId=revId,
                                          prevId=prevId)
        project.head = revision
        session.add(project)
        session.add(revision)
        session.commit()
        resp.status = falcon.HTTP_200
        resp.body = xmlSuccess({'revId': revId})
        if created:
            revision.save(contents)


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
        resp.body = formatXML(success)


class CreateCourse(object):

    def on_get(self, req, resp):
        session = Session()
        user = auth(session, req, resp)
        name = req.get_param('name')
        courseId = generateCourseId()
        course = Course(courseId=courseId, name=name, teachers=[user])
        session.commit()
        el = Elt('success', {'courseId': courseId})
        resp.status = falcon.HTTP_200
        resp.body = formatXML(el)


sql_engine = sqlengine.create_engine('sqlite:///snap.sqlite', echo=False)
sql_connection = sql_engine.connect()
Session = sessionmaker(bind=sql_engine)

Base.metadata.create_all(sql_engine)

app = falcon.API()

app.add_route('/createUser', CreateUser())
app.add_route('/createProject', CreateProject())
app.add_route('/listProjects', ListProjects())
app.add_route('/saveProject', SaveProject())
app.add_route('/createCourse', CreateCourse())

app.add_error_handler(Exception, handle_exception)
app.add_error_handler(ServerException, ServerException.handle_callback)


def main():
    http = gevent.wsgi.WSGIServer(('', 5000), app)
    http.serve_forever()

if __name__ == '__main__':
    main()
