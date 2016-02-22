#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import time
import re
import hmac
import string
import hashlib
import random
import json
import logging
import datetime 

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post = self)

class User(db.Model):
    username = db.StringProperty(required = True)
    hashed_pw = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

#num_of_posts = db.GqlQuery("SELECT * FROM Post").count()

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

##class MainPage(Handler):
##    def get(self):
##        if self.request.path == '/':
##            posts = db.GqlQuery("SELECT * FROM Post "
##                                "ORDER BY created DESC "
##                                "LIMIT 10")
##        else:
##            i = self.request.path[1:]
##            posts = db.GqlQuery("SELECT * FROM Post "
##                                "WHERE index=" + i)
##            
##        self.render('home.html', posts = posts)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    if h == make_pw_hash(name, pw, salt):
        return True
    
SECRET = 'JBqwVPQuUI'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class SignupHandler(Handler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        else:
            user_exists = db.GqlQuery("SELECT * FROM User "
                                      "WHERE username='%s'" % username).get()
            if user_exists:
                params['error_username'] = "Username already exists."
                have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            hashed_pw = make_pw_hash(username, password)
            user = User(username=username, hashed_pw=hashed_pw, email=email)
            user.put()
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s;Path=/' % make_secure_val(str(user.key().id())))
            self.redirect('/welcome')

class CheckLoginHandler(Handler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_cookie = self.request.cookies.get('user_id')
        u_id = user_cookie and check_secure_val(user_cookie)
        self.user = u_id and User.get_by_id(int(u_id))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'
            
    def get_posts(self, update = False, post_id = None):
        if post_id: key = str(post_id)
        else: key = 'front'
        value = memcache.get(key)
        if value is None or update:
            if key == 'front':
                posts = db.GqlQuery("select * from Post "
                                    "order by created desc "
                                    "limit 10")
                #prevent the running of multiple queries
                #more information about this in ascii-chan
                posts = list(posts)
            else:
                post = Post.get_by_id(int(post_id))
                if not post: return
                posts = [post]
            g_time = datetime.datetime.utcnow()
            value = (posts, g_time)
            memcache.set(key, value)
        
        return value
        

class WelcomeHandler(CheckLoginHandler):
    def get(self):
        username = self.user and self.user.username
        if username:
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

class MainPage(CheckLoginHandler):    
    def jsonize(self, p):
        d = {}
        d['content'] = p.content
        d['subject'] = p.subject
        d['created'] = p.created.strftime("%a %b %d %X %Y")
        d['last_modified'] = p.last_modified.strftime("%a %b %d %X %Y")
        return d
    
    def get(self, post_id):
        if post_id == '':
            if self.format == 'json':
                json_list = []
                for p in posts:
                    json_list.append(self.jsonize(p))
                json_list = json.dumps(json_list)
                self.response.headers['Content-Type'] = 'application/json'
                self.write(json_list)
                return
            posts, g_time = self.get_posts()                         
        else:
##            key = db.Key.from_path('Post', int(post_id))
##            post = db.get(key)
            #post = Post.get_by_id(int(post_id))
            #posts = [post] 
            value = self.get_posts(post_id = post_id)
            if not value:
                self.write("<h1>No such post!</h1>")
                return
            posts, g_time = value

            if self.format == 'json':
                json_item = json.dumps(self.jsonize(post))
                self.response.headers['Content-Type'] = 'application/json'
                self.write(json_item)
                return
        time_passed = (datetime.datetime.utcnow() - g_time).total_seconds()
        username = self.user and self.user.username
        self.render('home.html', posts = posts, username = username, time_passed = time_passed)    
        

class NewHandler(CheckLoginHandler):
    def render_new(self, subject = '', content = '', error = ''):
        username = self.user and self.user.username
        if username:
            self.render('new.html', subject = subject,
                        content = content, error = error)
        else:
            self.redirect('signup')
        
    def get(self):
        self.render_new()

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
#           global num_of_posts
#           num_of_posts += 1
            post = Post(subject = subject, content = content)
            post.put()
            self.get_posts(update = True)

            time.sleep(0.1)
            self.redirect('/%s' % post.key().id())
        else:
            error = 'Please enter both subject and cotnent!'
            self.render_new(subject, content, error)

class LoginHandler(Handler):
    def get(self):
        self.render('login.html', error = '')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % username).get()
        if user and valid_pw(username, password, user.hashed_pw):
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s;Path=/' % make_secure_val(str(user.key().id())))
            self.redirect('/welcome')
        else:
            self.render('login.html', error='Invalid login.')

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=;Path=/')
        self.redirect('/signup')
        
class FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')

app = webapp2.WSGIApplication([('/([0-9]*)', MainPage),
                               ('/([0-9]*)/?(?:\.json)?', MainPage),
                               ('/newpost', NewHandler),
                               ('/signup', SignupHandler),
                               ('/welcome', WelcomeHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/flush', FlushHandler)], debug=True)
