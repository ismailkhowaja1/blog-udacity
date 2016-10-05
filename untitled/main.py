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

# importing libraries
import hashlib
import hmac
import os
import random
import re
import string

import jinja2
import webapp2
from google.appengine.ext import db

# setting jinja env to get templates
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# ---Filters for formatting ---

# replacing new line with br tag
def letitpass(s):
    return s.replace('\n', '<br>')


# format date and time
def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    return value.strftime(format)


jinja_env.filters['letitpass'] = letitpass
jinja_env.filters['datetimeformat'] = datetimeformat

# secret for salting
SECRET = "nonoYouCannotGetIn!"


# render templates
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# create secure value of string
def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())


# verifying secure value created above
def check_secure_val(secure_val):
    if secure_val:
        val = secure_val.split('|')[0]
        if secure_val == make_secure_val(val):
            return val

# user methods
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# make the password hash to enhance security
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    hashval = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, hashval)

# check the password validity for login purposes
def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


# class to create blog post with title, content
# when was created, author,
# how many likes, how many comments

class BlogPost(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)
    liked_by = db.ListProperty(item_type=str)

    # class method to render post
    def render(self):
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return NewComment.all().filter("post = ", str(self.key().id()))


class NewComment(db.Model):
    comment = db.TextProperty()
    post = db.StringProperty(required=True)
    commented_by = db.StringProperty()


# user class to create user object with name, password, email
class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # get methods by name, and id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

        # -- get methods ends --#

    # register method to generate object
    @classmethod
    def register(cls, name, pwd, email=None):
        pw_hash = make_pw_hash(name, pwd)
        return User(username=name,
                    password_hash=pw_hash,
                    email=email
                    )

    # login method
    @classmethod
    def login(cls, name, pwd):
        u = cls.by_name(name)
        if u and valid_pw(name, pwd, u.password_hash):
            return u


# blog handler have helper classes to write and render content
class BlogHandler(webapp2.RequestHandler):
    # helper method for write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # get the template from jinjg and rendered
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    # helper method to display on the web
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # set secure cookie to remember user
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; path=/' % (name, cookie_val)
        )

    # read cookie to validate
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # login user into blog
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # log out user from blog
    def logout(self):
        self.response.headers.add_header('Set-Cookie', "user_id=; path=/")

    # initialize user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# new post handler to handle new post into blog
class NewPostHandler(BlogHandler):
    # render the new post in blog
    def render_newpost(self, title="", content="", error=""):
        if self.user:
            self.render("newpost.html",
                        title=title,
                        content=content,
                        error=error)
        else:
            self.redirect("/login")

    def get(self):
        self.render_newpost()

    """"""
    # this method will get the values from newpost.
    #  and create a blogpost and save in database
    def post(self):
        if not self.user:
            return self.redirect("/login")
        title = self.request.get("title")
        content = self.request.get("content")
        author = self.request.get("author")

        if title and content:
            b = BlogPost(title=title,
                         content=content,
                         author=author,
                         likes=0)
            # inserting blog post in database
            b.put()
            self.redirect('/%s' % str(b.key().id()))
        else:
            error = "we need both title and content"
            self.render_newpost(title, content, error)


# this handler helps to render the posts in database
class MainHandler(BlogHandler):
    def render_posts(self, title="", content="", error=""):
        posts = db.GqlQuery("SELECT * FROM BlogPost "
                            "ORDER BY created DESC limit 10")
        self.render("posts.html",
                    title=title,
                    content=content,
                    posts=posts,
                    error=error)

    def get(self):
        self.render_posts()


# validate methods for sign up

# these are provided method to validate entries for username, password, email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


USER_PASS = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and USER_PASS.match(password)


USER_EM = re.compile(r"[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return not email or USER_EM.match(email)


# this handler helps to sign up  the new user and redirect to blog page
class SignUpHandler(BlogHandler):
    def get(self):
        self.render("signup.html")

    # take the details from the sign up form
    def post(self):
        error = False
        self.username = self.request.get("username")
        self.password = self.request.get("user_pwd")
        self.verify_password = self.request.get("verify_user_pwd")
        self.email = self.request.get("user_email")

        params = dict(username=self.username,
                      email=self.email)

        # check the errors of valid username, password, and email
        if not valid_username(self.username):
            params['error_username'] = 'that is not a valid user name'
            error = True

        if not valid_password(self.password):
            params['error_password'] = 'that is not a valid password'
            error = True

        elif self.password != self.verify_password:
            params['error_verify'] = 'password did not match'
            error = True

        if not valid_email(self.email):
            params['error_email'] = 'Email is not valid'
            error = True

        if error:
            # render sign up forms with an error messages
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# check to see if user already exists
class Register(SignUpHandler):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = "that user already exists"
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


# this is will help to logn in users and check for invalid entries
class Login(BlogHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("user_pwd")

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = "invalid login!!"
            self.render("login.html", error_login=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect("/")


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('thankyou.html', username=self.user.username)
        else:
            self.redirect('/signup')


class Delete(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("BlogPost", int(post_id))
            post = db.get(key)
            if post and post.author == self.user.username:
                self.render("deletepost.html", post=post)
                post.delete()
            else:
                self.redirect("/login")
        else:
            self.redirect("/login")


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class Edit(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if post.author != self.user.username:
                self.redirect("/login")
            self.render("editpost.html", post=post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            newTitle = self.request.get("title")
            newContent = self.request.get("content")
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if self.user.username == post.author:
                if newTitle == "" and newContent == "":
                    error_edit = "You cannot left blanks empty"
                    self.render("editpost.html",
                                error_edit=error_edit,
                                post=post)
                else:
                    post.title = newTitle
                    post.content = newContent
                    post.put()
                    self.redirect("/%s" % str(post.key().id()))
            else:
                self.redirect('/login')
        else:
            self.redirect("/login")


class Like(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            if post and self.user.username not in post.liked_by:
                post.likes = post.likes + 1
                post.liked_by.append(self.user.username)
                post.put()
                self.redirect("/")
            else:
                msg = "you cannot like more than one"
                self.render('/posts.html', error=msg)
                self.redirect("/")
        else:
            self.redirect("/login")


class Comment(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if post.author == self.user.username:
                self.redirect("/")
            self.render("comment.html", post=post, comment="")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            comment = self.request.get("comment")
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if post.author == self.user.username:
                self.redirect("/")
            if comment == "":
                error_comment = "You cannot left blanks empty"
                self.render("comment.html",
                            error_comment=error_comment,
                            post=post, comment=comment)
            else:
                commented_by = self.request.get("commented_by")
                c = NewComment(comment=comment,
                               post=post_id,
                               commented_by=commented_by)
                c.put()

                self.redirect("/")
        else:
            self.redirect('/login')

class UpdateComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('NewComment', int(comment_id))
            comment = db.get(key)
            self.render("updatecomment.html", comment=comment)

    def post(self, comment_id):
        if self.user:
            updated_cmnt = self.request.get("updated_comment")
            key = db.Key.from_path('NewComment', int(comment_id))
            comment = db.get(key)
            if not comment:
                self.error(404)
                return
            if self.user.username == comment.commented_by:
                if updated_cmnt != "" and comment.comment != "":
                    comment.comment = updated_cmnt
                    print updated_cmnt + "saddad"
                    comment.put()
                    self.redirect("/")
                else:
                    error = "you cannot leave blanks empty"
                    self.render("updatecomment.html",
                                error_update=error, comment=comment)

            else:
                error = "you cannot update some one else comment"
                self.render("updatecomment.html", error_update=error)
        else:
            self.redirect("/login")


class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path("NewComment", int(comment_id))
            comment = db.get(key)
            if comment and comment.commented_by == self.user.username:
                deleted = comment.comment
                self.render("deletecomment.html", deleted=deleted)
                comment.delete()
            else:
                self.redirect("/login")
        else:
            self.redirect("/login")


# handle handlers
app = webapp2.WSGIApplication([
    ('/newpost', NewPostHandler),
    ("/", MainHandler),
    ("/signup", Register),
    ("/welcome", Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/delete/([0-9]+)', Delete),
    ('/([0-9]+)', PostPage),
    ('/edit/([0-9]+)', Edit),
    ('/like/([0-9]+)', Like),
    ('/comment/([0-9]+)', Comment),
    ('/updatecomment/([0-9]+)', UpdateComment),
    ('/deletecomment/([0-9]+)', DeleteComment)

], debug=True)
