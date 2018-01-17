# Copyright 2016 Google Inc.
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

import os
import re

import webapp2
import jinja2

import string
import random
from random import *

import codecs
import hashlib
import hmac

from google.appengine.ext import db
####################################################
template_dir = os.path.join(
    os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

newpost_html = "newpost.html"
viewpost_html = "viewpost.html"
viewcomment_html = "viewcomment.html"
editpost_html = "editpost.html"
newcomment_html = "newcomment.html"
editcomment_html = "editcomment.html"
blog_html = "blogs.html"
signup_html = "signup.html"
login_html = "login.html"
welcome_html = "welcome.html"
SECRET = 'duiuyX9fE~Tb6.pIp&Zib-OsmYO,Gqi$^jb34tz75'
####################################################


def is_cookie_removed(cookie):
    regex = re.compile(r".+=;\s*Path=/")
    return regex.match(cookie)


def is_username_valid(username):
    regex = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return regex.match(username)


def is_password_valid(password):
    regex = re.compile(r"^.{3,20}$")
    return regex.match(password)


def is_email_valid(email):
    regex = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return regex.match(email)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


def make_pw_hash(name, hashed, salt=None):
    if not salt:
        salt = make_salt()
        hashed = hashlib.sha256(name + hashed + salt).hexdigest()
#    return bcrypt.hashpw(password, salt)
#    return '%s,%s' % (h, salt)
    return "-".join([hashed, salt])


def valid_pw(name, pw, hash_pw_with_salt):
    salt = hash_pw_with_salt.split("-")[1]
    return hash_pw_with_salt == make_pw_hash(name, pw, salt)


def make_salt():
    y = sample(string.letters, 5)
    return "".join(y)
#    return bcrypt.gensalt()


def check_user_loggedIn(self):
    #        self.response.headers["Content-Type"] = "text/plain"
    user_id_cookie = self.request.cookies.get("user")
    if user_id_cookie:
        user_id = user_id_cookie.split("|")[0]
        hashed_password_withSalt = user_id_cookie.split("|")[1]
        hashed_password = hashed_password_withSalt.split("-")[0]
        if user_id and valid_pw(
           user_id, hashed_password, hashed_password_withSalt):
            return True
        else:
            self.redirect("/signup")
    else:
        self.redirect("/signup")


def getUserHashedPassword():
    user_id_cookie = self.request.cookies.get("user")
    if user_id_cookie:
        user_id = user_id_cookie.split("|")[0]
        hashed_password_withSalt = user_id_cookie.split("|")[1]
        hashed_password = hashed_password_withSalt.split("-")[0]
        return hashed_password


def getUserName(self):
    user_id_cookie = self.request.cookies.get("user")
    if user_id_cookie:
        user_id = user_id_cookie.split("|")[0]
        return user_id


def check_user_ownsObject(obj):
    if obj:
        hashed_password = getUserHashedPassword()
        user = obj.user
        if user:
            return user.password == hashed_password


def getUserObjFromUserName(username):
    if username:
        return db.GqlQuery(
            "SELECT * FROM User WHERE username= :username",
            username=username).get()


def getUserObj(self):
    user_id = getUserName(self)
    if user_id:
        return db.GqlQuery(
            "SELECT * FROM User WHERE username= :username",
            username=user_id).get()
####################################################


class Handler(webapp2.RequestHandler):
    def writeToBrower(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **parms):
        t = jinja_env.get_template(template)
        return t.render(parms)

    def sendToClient(self, template, **kw):
        self.writeToBrower(self.render_str(template, **kw))
####################################################


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    salt = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)


####################################################


class Comment(db.Model):  # to create entitiy
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    username = db.StringProperty(required=True)
    blog_id = db.IntegerProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.body.replace('\n', '<br>')
        return render_str(newcomment_html, p=self)
####################################################


class Blog(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=False)
    likes_by_users = db.ListProperty(str)

    def render(self):
        self._render_text = self.body.replace('\n', '<br>')
        return render_str(newpost_html, p=self)
####################################################


class SignupHandler(Handler):
    def get(self):
        self.sendToClient(signup_html)

    def post(self):
        input_username = self.request.get("username")
        input_password = self.request.get("password")
        input_verify = self.request.get("verify")
        input_email = self.request.get("email")
        dictionary_values = {}

        valid_username = is_username_valid(input_username)
        if valid_username:
            dictionary_values["valid_username"] = input_username
        else:
            dictionary_values["error_username"] = "Error with your Username."

        valid_password = is_password_valid(input_password)
        if input_password == input_verify:
            if not valid_password:
                dictionary_values["error_password"] = "Error - password."
        else:
            dictionary_values["error_verify"] = "Your passwords do not match."
        valid_email = is_email_valid(input_email)
        if valid_email:
            dictionary_values["valid_email"] = input_email
        else:
            dictionary_values["error_email"] = "Error with your Email."
        if valid_username and valid_password:
            hashed_password_withSalt = make_pw_hash(
                input_username, input_password)
            user = getUserObjFromUserName(input_username)
            if user:
                dictionary_values["error_username"] = "Dublicate User."
                self.sendToClient(
                    signup_html, dictionary_values=dictionary_values)
            else:
                a = User(
                    username=input_username, password=hashed_password_withSalt,
                    email=input_email)
                a.put()
                self.response.headers.add_header(
                    "Set-Cookie", "user=%s|%s;Path=/" % (
                        str(input_username), hashed_password_withSalt))
                self.redirect("/welcome")
        else:
            self.sendToClient(
                signup_html, dictionary_values=dictionary_values)
####################################################


class LogoutHandler(Handler):
    def get(self):
        self.logUserOut()

    def post(self):
        self.logUserOut()

    def logUserOut(self):
        self.response.headers.add_header("Set-Cookie", "user=; Path=/")
        self.redirect("/signup")
####################################################


class LoginHandler(Handler):
    def get(self):
        self.sendToClient(login_html)

    def post(self):
        input_username = self.request.get("username")
        input_password = self.request.get("password")
        dictionary_values = {}

        valid_username = is_username_valid(input_username)
        if valid_username:
            dictionary_values["valid_username"] = input_username
        else:
            dictionary_values["error"] = "Invalid Login"

        valid_password = is_password_valid(input_password)
        if not valid_password:
            dictionary_values["error_"] = "Invalid Login"

        dbuser = db.GqlQuery(
            "SELECT * FROM User WHERE username = :username",
            username=input_username)
        user = dbuser.get()
        if user:
            hashed_password_withSalt = user.password
            hashed_password = hashed_password_withSalt.split("-")[0]
            salt = hashed_password_withSalt.split("-")[1]
            verifyHash = make_pw_hash(input_username, hashed_password, salt)
            if valid_pw(user.username, hashed_password, verifyHash):
                self.response.headers.add_header(
                    "Set-Cookie", "user=%s|%s;Path=/" % (
                        str(user.username), str(verifyHash)))
                self.redirect("/welcome")
            else:
                self.sendToClient(
                    signup_html, dictionary_values=dictionary_values)
        else:
            self.sendToClient(signup_html)
####################################################


class WelcomeHandler(Handler):
    def get(self):
        if check_user_loggedIn(self):
            user_id_cookie = self.request.cookies.get("user")
            if user_id_cookie:
                user_id = user_id_cookie.split("|")[0]
                self.sendToClient(welcome_html, user_id=user_id)
####################################################


class MainPage(Handler):
    def get(self):
        self.response.headers["Content-Type"] = "text/plain"
        visits = 0
        visit_cookie_str = self.request.cookies.get("visitors")
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header(
            "Set-Cookie", "visitors=%s;Path=/" % new_cookie_val)
        if visits == 1001:
            self.writeToBrower("We Love yOu!")
        else:
            self.writeToBrower(
                "You went to the wrong page buddy! %s" % (
                    visit_cookie_str))
####################################################


class DeleteCommentHandler(Handler):
    def post(self, comment_id):
        if check_user_loggedIn(self):
            commment = Comment.get_by_id(int(comment_id))
            if not comment:
                self.error(404)
                return
            if commment.username == getUserName(self):
                commment.delete()
            self.redirect("/welcome")
####################################################


class NewCommentHandler(Handler):
    def render_entry(self, body="", error="", blog_id=""):
        if check_user_loggedIn(self):
            self.sendToClient(
                newcomment_html, body=body,
                error=error, blog_id=blog_id)

    def get(self, blog_id):
        self.render_entry("", "", blog_id)

    def post(self, blog_id):
        if check_user_loggedIn(self):
            body = self.request.get("body")
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)
            if body and blog:
                a = Comment(
                    body=body, username=getUserName(self),
                    blog_id=int(blog_id))
                a.put()
                self.redirect("/view_post/%d" % int(blog_id))
            else:
                error = "we need both a body!"
                self.render_entry(body, error, blog_id)
####################################################


class EditCommentHandler(Handler):
    def render_entry(self, body="", error="", comment_id=""):
            self.sendToClient(
                editcomment_html, body=body, error=error,
                comment_id=comment_id)

    def get(self, comment_id):
        if check_user_loggedIn(self):
            comment = Comment.get_by_id(int(comment_id))
            if not comment:
                self.error(404)
                return
            if comment and commment.username == getUserName(self):
                self.render_entry(comment.body, "", comment_id)
            else:
                self.redirect("/welcome")

    def post(self, comment_id):
        if check_user_loggedIn(self):
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)
            if not comment and not blog:
                self.error(404)
                return
            body = self.request.get("body")
            if body and commment.username == getUserName(self):
                comment.body = body
                comment.put()
                self.redirect("/view_comment/%d" % int(comment_id))
            else:
                error = "we need a body!"
                self.render_entry(body, error, comment_id)
####################################################


class EditPostHandler(Handler):
    def render_entry(self, title="", body="", error="", post_id=""):
        if check_user_loggedIn(self):
            self.sendToClient(
                editpost_html, title=title, body=body,
                error=error, post_id=post_id)

    def get(self, post_id):
        if check_user_loggedIn(self):
            post = Blog.get_by_id(int(post_id))
            if not post:
                self.error(404)
                return
            if post and post.username == getUserName(self):
                self.render_entry(post.title, post.body, "", post_id)
            else:
                self.redirect("/welcome")

    def post(self, post_id):
        if check_user_loggedIn(self):
            blogKey = db.Key.from_path('Blog', int(post_id))
            blog = db.get(blogKey)
            if not blog:
                self.error(404)
                return
            title = self.request.get("title")
            body = self.request.get("body")
            if body and title and blog.username == getUserName(self):
                blog.title = title
                blog.body = body
                blog.put()
                self.redirect("/view_post/%d" % int(post_id))
            else:
                error = "we need both a title and body!"
                self.render_entry(title, body, error)
####################################################


class CancelPostHandler(Handler):
    def post(self, post_id):
        if check_user_loggedIn(self):
            blogKey = db.Key.from_path('Blog', int(post_id))
            blog = db.get(blogKey)
            if not blog:
                self.error(404)
                return
            comments = db.GqlQuery(
                "Select * From Comment Order By created DESC")
            if blog:
                self.sendToClient(
                    viewpost_html, blog=blog, comments=comments,
                    user=getUserObj(self))
            else:
                self.redirect("/welcome")
####################################################


class CancelCommentHandler(Handler):
    def post(self, comment_id):
        if check_user_loggedIn(self):
            self.redirect("/view_comment/%d" % int(comment_id))
####################################################


class DeletePostHandler(Handler):
    def post(self, post_id):
        if check_user_loggedIn(self):
            post = Blog.get_by_id(int(post_id))
            if not post:
                self.error(404)
                return
            if post.username == getUserName(self):
                post.delete()
            self.redirect("/welcome")
####################################################


class LikePostHandler(Handler):
    def post(self, post_id):
        if check_user_loggedIn(self):
            key = db.Key.from_path('Blog', int(post_id))
            blog = db.get(key)
            if not blog:
                self.error(404)
                return
            username = getUserName(self)
            if blog:
                if blog.username == username:
                    self.redirect("/welcome")
                else:
                    if blog.likes is None:
                        blog.likes = 0
                    if username in blog.likes_by_users:
                        blog.likes -= 1
                        blog.likes_by_users.remove(username)
                        blog.put()
                    else:
                        blog.likes += 1
                        blog.likes_by_users.append(username)
                        blog.put()

            self.redirect("/view_post/%s" % int(post_id))
####################################################


class ViewCommentHandler(Handler):
    def get(self, comment_id):
        if check_user_loggedIn(self):
            comment = Comment.get_by_id(int(comment_id))
            if not comment:
                self.error(404)
                return
            if comment:
                self.sendToClient(
                    viewcomment_html, comment=comment,
                    user=getUserObj(self))
            else:
                self.redirect("/welcome")
####################################################


class ViewPostHandler(Handler):
    def get(self, post_id):
        if check_user_loggedIn(self):
            blog = Blog.get_by_id(int(post_id))
            if not blog:
                self.error(404)
                return
            comments = db.GqlQuery(
                "Select * From Comment Order By created DESC")
            if blog:
                self.sendToClient(
                    viewpost_html, blog=blog, comments=comments,
                    user=getUserObj(self))
            else:
                self.redirect("/welcome")
####################################################


class NewPostHandler(Handler):
    def render_entry(self, title="", body="", error=""):
            self.sendToClient(
                newpost_html, title=title, body=body, error=error)

    def get(self):
        if check_user_loggedIn(self):
            self.render_entry()

    def post(self):
        if check_user_loggedIn(self):
            title = self.request.get("title")
            body = self.request.get("body")
            if body and title:
                a = Blog(
                    title=title, body=body, username=getUserName(self))
                b = a.put()
                self.redirect("/view_post/%d" % b.id())
            else:
                error = "we need both a title and body!"
                self.render_entry(title, body, error)
####################################################


class BlogHandler(Handler):
    def get(self):
        if check_user_loggedIn(self):
            blogs = db.GqlQuery(
                "Select * From Blog Order By created DESC")
            comments = db.GqlQuery(
                "Select * From Comment Order By created DESC")
            self.sendToClient(
                blog_html, blogs=blogs,
                comments=comments, user=getUserObj(self))
####################################################
app = webapp2.WSGIApplication([
    ("/", MainPage),
    ("/blogs", BlogHandler),
    ("/new_post", NewPostHandler),
    ("/view_post/([0-9]+)", ViewPostHandler),
    ("/edit_post/([0-9]+)", EditPostHandler),
    ("/delete_post/([0-9]+)", DeletePostHandler),
    ("/like_post/([0-9]+)", LikePostHandler),
    ("/new_comment/([0-9]+)", NewCommentHandler),
    ("/edit_comment/([0-9]+)", EditCommentHandler),
    ("/delete_comment/([0-9]+)", DeleteCommentHandler),
    ("/view_comment/([0-9]+)", ViewCommentHandler),
    ("/signup", SignupHandler),
    ("/welcome", WelcomeHandler),
    ("/login", LoginHandler),
    ("/logout", LogoutHandler),
    ("/cancel_post/([0-9]+)", CancelPostHandler),
    ("/cancel_comment/([0-9]+)", CancelCommentHandler)
                               ], debug=True)
"""users:
#LoginHandler
#DeleteCommentHandler

#        blogs = db.GqlQuery("Select * From Blog Order By created DESC")
#        for blog in blogs:
#            blog.delete()
#        users = db.GqlQuery("Select * From User Order By created DESC")
#        for user in users:
#            user.delete()
#        comments = db.GqlQuery("Select * From Comment Order By created DESC")
#        for comment in comments:
#                comment.delete()
"""
