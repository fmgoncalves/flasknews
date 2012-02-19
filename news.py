#!/usr/bin/env python

from flask import Flask, render_template, request, url_for, redirect
from flaskext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
db = SQLAlchemy(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    link = db.Column(db.String(255))
    upvotes = db.Column(db.Integer)
    downvotes = db.Column(db.Integer)

    def __init__(self, title, link):
        self.title = title
        self.link = link
        self.upvotes = self.downvotes = 0

    def __repr__(self):
        return '<Post %r (%r)>' % (self.title, self.link)

@app.route('/')
def index():
    posts = Post.query.order_by('-upvotes').all()
    return render_template('front.html', posts=posts)

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        submission = Post(request.form['title'], request.form['link'])
        db.session.add(submission)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('submit.html')

@app.route('/vote/<int:pid>', methods=['GET'])
def vote(pid):
    direction = request.args.get('d','up')

    p = Post.query.filter_by(id=pid).all()[0]
    if direction == 'up':
        p.upvotes += 1
    else:
        p.downvotes += 1

    db.session.add(p)
    db.session.commit()
    return redirect(url_for('index'))


if __name__=='__main__':
    app.run(debug=True)
