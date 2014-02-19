#!/usr/bin/env python

from flask import Flask, render_template, request, url_for, session, redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.contrib.atom import AtomFeed

from functools import wraps

from time import gmtime, ctime
from calendar import timegm
from datetime import datetime
from random import randint

from collections import defaultdict

from hashlib import sha512
import sys

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
app.secret_key = 'Z\x1f7Y\xa53/\x9f\x9b\xc6\xc3V\x07GLA\xdd}zl\x92W\xad\xfb'
db = SQLAlchemy(app)

tag_colors = ['#FF9900', '#424242', '#E9E9E9', '#BCBCBC', '#3299BB']

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
        if check_auth(request.form["username"], request.form["password"]):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid Username/Password')
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not 'username' in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

###

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.deferred(db.Column(db.String))
    link = db.Column(db.String(255))
    tag = db.Column(db.String(255))
    submitter = db.Column(db.String, db.ForeignKey('user.username'))
    time = db.Column(db.Integer)

    def __init__(self, title, link, tag, submitter, content=str()):
        self.id = int(sha512(u'{}{}{}'.format(title,link,content,tag).encode("utf-8")).hexdigest(),base=16) % sys.maxint
        self.title = title
        self.link = link
        self.tag = tag
        self.submitter = submitter
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
            votes_list = Vote.query.filter_by(post=self.id).all()
            # TODO sum the values in the database
            return sum(map(lambda x: x.value, votes_list))
        except ZeroDivisionError:
            return 0

    def tagcolor(self):
        tag = self.tag
        color_idx = int(sha512(u'{}'.format(tag.lower()).encode('utf-8')).hexdigest(),base=16) % len(tag_colors)
        return tag_colors[color_idx]


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_post = db.Column(db.Integer, db.ForeignKey('post.id'))
    content = db.Column(db.String(255))
    submitter = db.Column(db.String, db.ForeignKey('user.username'))
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
    posts = sorted(Post.query.all(), key=lambda x: x.time + (x.score() * 600), reverse=True)
    return render_template('front.html', posts=posts)

@app.route('/comments/<int:pid>', methods=['GET'])
def comments(pid):
    p = Post.query.filter_by(id=pid).first()
    comments = sorted(Comment.query.filter_by(parent_post=p.id), key=lambda x: x.time, reverse=False)
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
        submission = Post(request.form['title'], request.form['link'], request.form['tag'], session['username'], request.form['content'])
        vote(submission.id)
        db.session.add(submission)
        try:
            db.session.commit()
            return redirect(url_for('index'))
        except IntegrityError as e:
            return render_template('submit.html', error='Duplicated submission')
        except:
            return render_template('submit.html', error='Failed to submit')
    else:
        return render_template('submit.html')

class Vote(db.Model):
    post = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
    submitter = db.Column(db.String, db.ForeignKey('user.username'), primary_key=True)
    value = db.Column(db.Integer)

    def __init__(self, post_id, submitter, value):
        self.post = post_id
        self.submitter = submitter
        self.value = value

    def __repr__(self):
        return '<%rvote on %r by %r>' % ( 'up' if self.value == 1 else 'down', self.post, self.submitter)

@app.route('/vote/<int:pid>', methods=['GET'])
@requires_auth
def vote(pid):
    voter = session['username']

    vote = 0
    direction = request.args.get('d','up')

    if direction == 'up':
        vote = 1
    elif direction == 'down':
        vote = -1
    elif direction == 'random':
        vote = randint(-1,1)

    if vote != 0:
        v = Vote(pid, session['username'], vote)
        db.session.add(v)
        try:
            db.session.commit()
        except IntegrityError as e:
            print 'User {} tried to repeat vote on {}'.format(session['username'], pid)

    return redirect(url_for('index'))


### FEED

@app.route('/recent.atom')
def recent_feed():
    feed = AtomFeed('Recent Articles',
        feed_url=request.url, url=request.url_root)
    posts = Post.query.order_by(Post.time.desc()).limit(50).all()
    for post in posts:
        feed.add(
            post.title,
            post.content,
            content_type='text',
            author=post.submitter,
            url=url_for('comments',pid=post.id),
            links=[ { 'href' : post.link } ],
            #categories=list(), # TODO need to have post tags first
            updated=datetime.utcfromtimestamp(post.time)
        )
    return feed.get_response()

###

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

    if options.create_db:
        db.create_all()
        sys.exit(0)
    elif options.add_user:
        add_user()
        sys.exit(0)

    app.run(host=options.host,port=options.port,debug=options.debug)
