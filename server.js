
function SnapServer(url) {
  this.url = url;
  this.clear();
}

SnapServer.prototype.clear = function () {
  this.username = null;
  this.password = null;
  this.email = null;
  this.session = null;
  this.currentProjId = null;
}

SnapServer.prototype._encodeQueryString = function (params) {
  var str = [];
  for (var key in params) {
    if (params.hasOwnProperty(key)) {
      str.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
    }
  }
  return str.join('&');
}

SnapServer.prototype.get = function (
    api,
    params,
    onError,
    onSuccess,
    url
    ) {
  return this._request('GET', '', api, params, onError, onSuccess, url);
}

SnapServer.prototype.post = function (
    data,
    api,
    params,
    onError,
    onSuccess,
    url
    ) {
  return this._request('POST', data, api, params, onError, onSuccess, url);
}

SnapServer.prototype._request = function (
    verb,
    data,
    api,
    params,
    onError,
    onSuccess,
    url
    ) {
  var request = XMLHttpRequest();
  var myself = this;
  function encodeQues
  try {
    if (url === undefined) {
      url = this.url + api + '?' + this._encodeQueryString(params);
    }
    if (this.username === null || this.password === null) {
      request.open(
          "GET",
          url,
          true
      );
    } else {
      request.open(
          "GET",
          url,
          true,
          this.username,
          this.password
      );
      request.setRequestHeader(
          'Snap-Server-Authorization',
          this.encodeAuth()
      );
    }
    request.onreadystatechange = function () {
      if (request.readyState === 4) {
        if (request.status !== 200 ||
            !request.responseXML ||
            request.responseXML.firstChild.nodeName !== 'success') {
          var msg;
          if (request.responseXML.firstChild &&
            request.responseXML.firstChild.nodeName === 'error') {
            msg = request.responseXML.firstChild.getAttribute('reason');
          }
          else {
            msg = request.responseText;
          }
          onError.call(
              myself,
              msg
          );
        }
        else {
          try {
            onSuccess.call(
                myself,
                request.responseXML
            );
          } catch (err) {
            onError.call(myself, err.toString());
          }
        }
      }
    };
    request.send(data);
  } catch (err) {
    onError.call(myself, err.toString());
  }
};
  
// Attempts to create a user, given a username and password.
// Calls corresponding callback, with no useful data.
SnapServer.prototype.signup = function (
    username,
    email,
    onSuccess,
    onError
    ) {
  this.username = username;
  this.email = email;
  this.get('createUser', {
    userName: username,
    email: email
  }, onError, function (res) {
    var user = res.getElementsByTagName('user')[0];
    if (this.username != user.getAttribute('userName')) {
      throw 'Did not create correct username!';
    }
    if (this.email != user.getAttribute('email')) {
      throw 'Did not create correct email!';
    }
    this.password = user.getAttribute('password');
  });
};

SnapServer.prototype.getPublicProject = function (
    id,
    onSuccess,
    onError
    ) {
  var username;
  var projectName;
  try {
    var username = id.match(/Username=([^&]+)/)[1];
    var projectName = id.match(/projectName=([^&]+)/)[1];
  } catch (err) {
    onError.call(null, err.toString(), 'getProjectByName');
  }
  this.get('getProjectByName', {
    userName: username,
    sharedName: projectName,
  }, onError, function (res) {
    var uri = res.getElementsByTagName('URI')[0].nodeValue;
    this.get('', {
    }, onError, function (res) {
      onSuccess(res.getElementsByTagName('data')[0].nodeValue);
    }, uri);
  });
};

SnapServer.prototype.resetPassword = function (
    username,
    onSuccess,
    onError
    ) {
  this.get('resetPassword', {
    userName: this.username,
  }, onError, onSuccess);
};


SnapServer.prototype.saveProjectData = function (
    projName,
    data,
    onError,
    onSuccess
    ) {
  function save () {
    this.post('saveProject', {
      projId: this.currentProjId,
      sharedName: projName,
    }, onError, onSuccess);
  }
  if (this.currentProjId === null) {
    this.get('createProj', {
    }, onError, function (res) {
      this.currentProjId = res.firstChild.getAttribute('projId');
      save();
    });
  } else {
    save();
  }
};

SnapServer.prototype.listProjects = function (
    onError,
    onSuccess
    ) {
  this.get('listProjects', {
  }, onError, onSuccess);
};

SnapServer.prototype.getProjectList = function (
    onSuccess,
    onError
    ) {
  this.listProjects(
  function (err) {
    onError.call(null, err, 'SaveProject');
  },
  function (res) {
    var proj_list = [];
    var projs = res.getElementsByTagName('project');
    for (var i in projs) {
      var elem = projs[i];
      var names = elem.getElementsByTagName('sharedNames');
      if (names.length === 0) {
        var names = elem.getElementsByTagName('projId');
      }
      proj_list.push({ProjectName: names[0].nodeValue});
    }
    onSuccess(proj_list);
  });
};

// Only here for API Emulation purposes
SnapSever.prototype.hasProtocol = function () {
  return this.url.toLowerCase().indexOf('http') === 0;
};

SnapServer.prototype.connect = function (
    onSuccess,
    onError
    ) {
  this.get('listProjects', {}, onError, onSuccess);
};

SnapServer.prototype.login = function (
    username,
    password,
    onSuccess,
    onError
    ) {
  this.username = username;
  this.password = password;
  this.get('listProjects', {}, onError, onSuccess);
};

SnapServer.prototype.rawLogin = SnapServer.prototype.login;

SnapServer.prototype.reconnect = function (
    onSuccess,
    onError
  ) {
  if (!(this.username && this.password)) {
    this.message('You are not logged in');
    return;
  }
  this.login(
      this.username,
      this.password,
      onSuccess,
      onError
  );
};

SnapServer.prototype.saveProject = function (
    ide,
    onSuccess,
    onError
    ) {
  var pdata = ide.serializer.serialize(ide.stage);

  // check if serialized data can be parsed back again
  try {
      ide.serializer.parse(pdata);
  } catch (err) {
      ide.showMessage('Serialization of program data failed:\n' + err);
      throw new Error('Serialization of program data failed:\n' + err);
  }
  this.saveProjectData(
    ide.projectName,
    pdata,
    onError,
    onSuccess
    );
};

SnapServer.prototype.changePassword = function (
    oldPassword,
    newPassword,
    onSuccess,
    onError
    ) {
  this.get('changePassword', {
    newPassword: newPassword,
  }, onError, onSuccess);
};

SnapServer.prototype.callURL = nop;
SnapServer.prototype.logout = nop;
SnapServer.prototype.disconnect = nop;
SnapServer.prototype.callService = nop;

SnapServer.prototype.encodeDict = function (dict) {
    var str = '',
        pair,
        key;
    if (!dict) {return null; }
    for (key in dict) {
        if (dict.hasOwnProperty(key)) {
            pair = encodeURIComponent(key)
                + '='
                + encodeURIComponent(dict[key]);
            if (str.length > 0) {
                str += '&';
            }
            str += pair;
        }
    }
    return str;
};


// SnapServer: user messages (to be overridden)

SnapServer.prototype.message = function (string) {
    alert(string);
};

var Cloud;

//var SnapCloud = new SnapServer('inst.eecs.berkeley.edu/~ee40-sl/venv/server/snap.cgi');
var SnapCloud = new SnapServer('http://localhost:5000');
