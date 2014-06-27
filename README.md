#snap-server

A new backend for saving and sharing Snap! projects.

Dependencies:
sqlalchemy
Falcon
For decent performance, need Gevent

Supports Python 2.6 through 3.x


## Initial setup
1. Download and install git from http://git-scm.com/download/
2. Clone the repository with `git clone git@github.com:cs10/snap-server.git`
3. cd to the directory where you have cloned this repo
3. `sudo easy_install pip`
4. `pip install virtualenv`
5. `virtualenv --distribute virt`
6. `source virt/bin/activate` to activate the virtualenv - be sure to activate the virtualenv before taking any actions
7. `pip install -r requirements.txt` (Needed for any change to the requirements file)

##Running the server
1. cd to the directory where you have cloned this repo
2. `source virt/bin/activate`
3. `ps aux | grep 5000 | grep -v grep | awk '{print $2}' | xargs kill -9` will kill any processes running on port 5000.
4. `python dev.py` - it should be serving at http://localhost:5000

##Using the server
1. Open `http://localhost:5000/createUser` and enter info for a test user
2. Look at the bottom server.py to find the URL routes
   For example, try `http://localhost:5000/createProject` and `http://localhost:5000/loadProject`
3. You can can open a Python shell with `python -i`  - rest coming soon
