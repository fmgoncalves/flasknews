#!/usr/bin/env python

from flask import Flask, render_template, request, url_for, session, redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy

from functools import wraps

from time import gmtime, ctime
from calendar import timegm

from collections import defaultdict

from hashlib import sha512

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
app.secret_key = 'Z\x1f7Y\xa53/\x9f\x9b\xc6\xc3V\x07GLA\xdd}zl\x92W\xad\xfb'
db = SQLAlchemy(app)


### AUTHENTICATION

class User(db.Model):
    username = db.Column(db.String, primary_key=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, username, password):
        self.username = username
        self.password_hash = sha512(password).hexdigest()

def check_auth(username, password):
    user = User.query.filter_by(username=username).first()
    valid_auth = user and user.username == username and user.password_hash == sha512(password).hexdigest()
    return valid_auth

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        origin = request.form["origin"] if "origin" in request.form else 'index'
        if check_auth(request.form["username"], request.form["password"]):
            session['username'] = request.form['username']
            return redirect(url_for(origin))
        else:
            return render_template('login.html', origin=origin, error='Invalid Username/Password')
    else:
        origin = request.args.get('origin','index')
        return render_template('login.html', origin=origin)

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not 'username' in session:
            return redirect(url_for('login', origin=f.__name__))
        return f(*args, **kwargs)
    return decorated

###

vote_cache = defaultdict(set)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.String(255))
    link = db.Column(db.String(255))
    submitter = db.Column(db.String(255), db.ForeignKey('user.username'))
    upvotes = db.Column(db.Integer)
    downvotes = db.Column(db.Integer)
    time = db.Column(db.Integer)

    def __init__(self, title, link, submitter, content=str()):
        self.title = title
        self.link = link
        self.submitter = submitter
        self.upvotes = self.downvotes = 0
        self.time = timegm(gmtime())
        self.content = content

    def __repr__(self):
        return '<Post %r(%r) by %r>' % (self.title, self.score(), self.submitter)

    def prettytime(self):
        return ctime(self.time)

    def n_comments(self):
        return len(Comment.query.filter_by(parent_post=self.id).all())

    def score(self):
        try:
            return self.upvotes - self.downvotes
            #return (self.upvotes) / (self.upvotes + self.downvotes)
        except ZeroDivisionError:
            return 0

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_post = db.Column(db.Integer, db.ForeignKey('post.id'))
    content = db.Column(db.String(255))
    submitter = db.Column(db.String(255), db.ForeignKey('user.username'))
    time = db.Column(db.Integer)

    def __init__(self, post_id, content, submitter):
        self.parent_post = post_id
        self.content = content
        self.submitter = submitter
        self.time = timegm(gmtime())

    def __repr__(self):
        return '<Comment on %r by %r>' % (self.parent_post, self.submitter)

    def prettytime(self):
        return ctime(self.time)

@app.route('/')
def index():
    posts = sorted(Post.query.all(), key=lambda x: x.score(), reverse=True)
    return render_template('front.html', posts=posts)

@app.route('/comments/<int:pid>', methods=['GET'])
def comments(pid):
    p = Post.query.filter_by(id=pid).first()
    comments = sorted(Comment.query.filter_by(parent_post=p.id), key=lambda x: x.time, reverse=True)
    return render_template('comments.html', p=p, comments=comments)

@app.route('/comment', methods=['POST'])
@requires_auth
def comment():
    parent_post = request.form['pid']
    submission = Comment(parent_post, request.form['content'], session['username'])
    db.session.add(submission)
    db.session.commit()
    return redirect(url_for('comments',pid=parent_post))

@app.route('/submit', methods=['GET', 'POST'])
@requires_auth
def submit():
    if request.method == 'POST':
        submission = Post(request.form['title'], request.form['link'], session['username'], request.form['content'])
        submission.upvotes = 1
        vote_cache[submission.id].add(session['username'])
        db.session.add(submission)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('submit.html')


@app.route('/vote/<int:pid>', methods=['GET'])
@requires_auth
def vote(pid):
    voter = session['username']

    if voter not in vote_cache[pid]:
        direction = request.args.get('d','up')

        p = Post.query.filter_by(id=pid).first()
        if direction == 'up':
            p.upvotes += 1
        elif direction == 'down':
            p.downvotes += 1

        db.session.add(p)
        db.session.commit()

        vote_cache[pid].add(voter)

    return redirect(url_for('index'))


def add_user():
    username = raw_input('Username: ')
    
    if not username:
        print 'Username is mandatory'
        return
    
    MIN_PASSWORD_LENGTH = 4
    password = raw_input('Password: ')
    if len(password) < MIN_PASSWORD_LENGTH:
        print 'Password must be at least {} characters long'.format(MIN_PASSWORD_LENGTH)
        return

    if User.query.filter_by(username=username).count() > 0:
        print 'User {} already exists'.format(username)
    else:
        u = User(username, password)
        db.session.add(u)
        db.session.commit()
        print 'User {} added'.format(username)


if __name__=='__main__':
    
    import argparse

    optparser = argparse.ArgumentParser(description='FlaskNews')
    optparser.add_argument('--create_db', help='Create SQLite database.', action='store_true')
    optparser.add_argument('-d','--debug', help='Extended runtime info.', action='store_true')
    optparser.add_argument('--host', type=str, default='0.0.0.0', help='IP to serve site.')
    optparser.add_argument('-p','--port', type=int, default=8080, help='Port to serve site.')
    optparser.add_argument('--add_user', help='Add user credentials to database.', action='store_true')

    options = optparser.parse_args()

    import sys
    if options.create_db:
        db.create_all()
        sys.exit(0)
    elif options.add_user:
        add_user()
        sys.exit(0)

    app.run(host=options.host,port=options.port,debug=options.debug)
