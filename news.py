#!/usr/bin/env python

from flask import Flask, render_template, request, url_for, redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy

from functools import wraps

from time import gmtime, ctime
from calendar import timegm

from collections import defaultdict

from hashlib import sha512

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
db = SQLAlchemy(app)


### AUTHENTICATION

class User(db.Model):
    username = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, username, password):
        self.username = username
        self.password_hash = sha512(password).hexdigest()

def check_auth(username, password):
    valid_auth = False
    if username == 'admin' and password == 'password':
        valid_auth = True
    else:
        user = Post.query.filter_by(username=username).first()
        valid_auth = user.username == username and user.password_hash == sha512(password).hexdigest()
    return valid_auth

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Y u fake login?\n', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
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
    submission = Comment(parent_post, request.form['content'], request.authorization['username'])
    db.session.add(submission)
    db.session.commit()
    return redirect(url_for('comments',pid=parent_post))

@app.route('/submit', methods=['GET', 'POST'])
@requires_auth
def submit():
    if request.method == 'POST':
        submission = Post(request.form['title'], request.form['link'], request.authorization['username'], request.form['content'])
        db.session.add(submission)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('submit.html')


@app.route('/vote/<int:pid>', methods=['GET'])
@requires_auth
def vote(pid):
    voter = request.authorization['username']

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


if __name__=='__main__':
    import sys
    if '--create-db' in sys.argv:
        db.create_all()
        sys.exit(0)
    app.run(port=5001,debug=True)
