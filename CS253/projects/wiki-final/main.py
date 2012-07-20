import webapp2
import jinja2
import os
import re
import hashlib
import hmac
import random
import string
import json 
import time
import logging

#from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.ext.db import to_dict
from google.appengine.api import memcache


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
JSON_CONTENT_TYPE =  'application/json; charset=UTF-8'
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(''))
        
    def initialize(self, *a, **kw):
        logging.getLogger().setLevel(logging.DEBUG)
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and BlogUser.by_id(int(uid))
        
        
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
#import logging

# retrieves the top 10 blog posts from memcache.
# if there is none in the memcache or if it is an cache update request then
# the top 10 blog posts are read from the database and put into memcache
# finally return them
def top_posts(update_cache = False):
    key = 'top'
    time_key = 'time'
    posts = memcache.get(key)
    if posts is None or update_cache:
        #logging.debug("#########################:MAINPAGE DBQUERY")
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        posts = list(posts)
        memcache.set(key, posts)
        memcache.set(time_key,time.time())
    return posts

def get_time_diff_second(cache_key):
    cache_time = int(memcache.get(cache_key))
    diff = int(time.time() - cache_time);
    return diff;
        
def last__mainpage_query():
    time_key = 'time'
    return get_time_diff_second(time_key);

def cached_post(post_id, update_cache = False):
    post_key = str(post_id)
    post = memcache.get(post_key)
    post_time_key = 'time_%s' % str(post_id) 
    
    if post is None or update_cache:
        #logging.debug("#########################:PERMLINK DBQUERY")
        db_post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(db_post_key)
        memcache.set(post_key,post)
        memcache.set(post_time_key,time.time())
    
    return post

def last_permlink_query(post_id):
    post_time_key = 'time_%s' % str(post_id) 
    return get_time_diff_second(post_time_key);

class FlushMemCeche(BlogHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")
            
class MainPage(BlogHandler):
    def get(self,json_request=None):
        posts = top_posts()
        if json_request:
            self.response.headers['Content-Type'] = JSON_CONTENT_TYPE
            posts_list_of_dict = list()
            for post in posts:
                posts_list_of_dict.append(post.json_format())
            self.write(json.dumps(posts_list_of_dict))
        else:
            query_time = "queried %d seconds ago" % last__mainpage_query()
            self.render("front_page.html", posts=posts, query_time = query_time)

class NewPost(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect('/login')
            return
        self.render("newpost.html")
    def post(self):
        if not self.user:
            self.redirect('/login')
            return
        
        subject = self.request.get('subject')
        content = self.request.get('content')

        if not subject or not content:
            self.render("newpost.html", subject=subject, content=content, error="subject and content both required")
        else:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            top_posts(update_cache = True)
            cached_post(p.key().id(), update_cache = True)
            self.redirect("/%s" % (p.key().id()))
      
def blog_key(name='default'):
    return db.Key.from_path('blogs', name) 
    
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)
    def json_format(self):
        d_post = to_dict(self)
        d_post['created'] = self.created.strftime("%a %b %d %H:%M:%S %Y")
        d_post['last_modified'] = self.last_modified.strftime("%a %b %d %H:%M:%S %Y")
        return d_post
        
def users_key(group='default'):
    return db.Key.from_path('users', group)
class BlogUser(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())
    
    @classmethod
    def by_username(cls, username):
        u = cls.all().filter('username =', username).get()
        return u
    
    @classmethod
    def register(cls, username, password, email = None):
        password_hash = make_pw_hash(username,password)
        return cls(parent = users_key(), username = username, password_hash = password_hash, email = email)
    
    @classmethod
    def valid_login(cls, username, pw):
        u = cls.by_username(username)
        if u and valid_pw(username, pw, u.password_hash):
            return u
        
class PostPage(BlogHandler):
    def get(self, post_id, json_request=None):
        
        post = cached_post(post_id)
        if json_request:
            self.response.headers['Content-Type'] = JSON_CONTENT_TYPE
            if not post:
                self.write('{"error": 404}')
                return
            self.write(json.dumps(post.json_format()))
        else:                    
            if not post:
                self.error(404)
                return
            query_time = "queried %d seconds ago" % last_permlink_query(post_id)
            self.render("permalink.html", post=post, query_time = query_time)

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    
    def done(self, *a, **kw):
        raise NotImplementedError
    
class Register(Signup):
    def done(self):
        u = BlogUser.by_username(self.username)
        if u:
            self.render('signup-form.html',error_username='This user already exists');
            return
        u = BlogUser.register(self.username, self.password, self.email)
        u.put()
        self.login(u)
        self.redirect('/welcome')
    
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username)
        else:
            self.redirect('/signup')

class Login(BlogHandler):

    def get(self):
        #self.response.headers['Referer'] = self.request.headers.get('Referer')
        self.set_secure_cookie('lr-url', str(self.request.headers.get('Referer','')))
        
        if not self.user:
            self.render('login.html')
            
        else:
            self.redirect('/welcome')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        login_user = BlogUser.valid_login(username, password)
        if login_user:
            lr_url = self.read_secure_cookie('lr-url')
            redirect_url = str(lr_url) if lr_url else '/welcome' 
            self.login(login_user)
            self.redirect(redirect_url)
        else:
            self.render('login.html', error = 'Invalid login')


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect(self.request.headers.get('Referer'))

# there can be a (hidden) javascript calling this url /cookietest
# then a cookie is sent with the response
# when the user comes back to the site, it's easy to check if it's
# a returning or new user by checking the cookie
# good for tracking who is visiting a site and what are the sites
# a given user is visiting (if the same hidden javascript is in different pages
# and a user is visting them - google analytics)
class CookieTest(BlogHandler):
    def get(self):
        self.write(self.request.remote_addr)
        test = self.request.cookies.get('test', None)
        
        #if no cookie exists, new user
        if not test:
            self.response.headers.add_header('Set-Cookie', 'test=%s; Path=/' % str('test_value'))
        self.write(test)

        
###### Security stuff
SECRET = 'mysecret'
def hash_str(s):
    return hmac.new(SECRET, s, hashlib.sha256).hexdigest()
    #return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# returns a string of 5 random
# letters use python's random module.
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# returns a hashed password 
# of the format: 
# HASH(name + pw + salt),salt
# uses sha256
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s,%s' % (h, salt)

# returns True if a user's password 
# matches its hash.
def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

#app = webapp2.WSGIApplication([('/?', MainPage),
#                               ('/(.json)', MainPage),
#                               ('/rot13', Rot13),
#                               ('/signup', Register),
#                               ('/login', Login),
#                               ('/logout', Logout),
#                               ('/welcome', Welcome),
#                               ('/newpost', NewPost),
#                               ('/cookietest', CookieTest),
#                               ('/([0-9]+)', PostPage),
#                               ('/([0-9]+)(.json)', PostPage),
#                               ('/flush', FlushMemCeche)],
#                              debug=True)

############ final exam #############

def cached_page_version(page_name, version=None):
    pages = cached_history_pages(page_name)
    if len(pages) == 0:
        return None
    
    if not version:
        return pages.pop(0)
    else:
        for p in pages:
            if p.key().id() == int(version):
                return p;
    return None
        

def cached_history_pages(page_name, update_cache = False):
    page_name = str(page_name)
    key = 'history_' + page_name
    time_key = 'time_history_'+page_name
    pages = memcache.get(key)
    if pages is None or update_cache:
        pages = WikiEntity.all_by_name(page_name)
        pages = list(pages)
        memcache.set(key, pages)
        memcache.set(time_key,time.time())
    return pages

def wiki_key(name='default'):
    return db.Key.from_path('wikis', name) 

def last_wiki_page_query(page_name):
    page_time_key = 'time_history_%s' % str(page_name) 
    return get_time_diff_second(page_time_key);

class WikiEntity(db.Model):
    name = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    
    @classmethod
    def by_name(cls, name):
        e = cls.all_by_name(name).get()
        return e
    
    @classmethod
    def all_by_name(cls, name):
        pages = cls.all().filter('name =', name)
        pages.order('-created')
        
        #logging.debug("#########################:all_by_name"+ name)
        return pages

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("wiki_entity.html", e=self)
    
    def json_format(self):
        d_post = to_dict(self)
        d_post['created'] = self.created.strftime("%a %b %d %H:%M:%S %Y")
        d_post['last_modified'] = self.last_modified.strftime("%a %b %d %H:%M:%S %Y")
        return d_post

class EditPage(BlogHandler):
    def get(self, page_name):
        if not self.user:
            self.redirect('/login')
            return
        version = self.request.get('v','')
        entity = cached_page_version(page_name, version)
        login_area_links = self.get_login_navigation(page_name)
        self.render("wiki_edit.html", content = entity.content if entity else '', login_area_links = login_area_links)
    
    def post(self, page_name):
        if not self.user:
            self.redirect('/login')
            return
        
        page_name = str(page_name)
        content = self.request.get('content')

        if not content:
            login_area_links = self.get_login_navigation(page_name)
            self.render("wiki_edit.html", error="Content required", login_area_links = login_area_links)
        else:
            e = WikiEntity(parent=wiki_key(), name=page_name, content=content)
            e.put()
            cached_history_pages(page_name, update_cache = True)
            self.redirect("%s" % (page_name))
   
    def get_login_navigation(self, page_name):
        navigation_links = list()
        version = self.request.get('v','')

        if version:
            view_link = LoginAreaNavigation(href = page_name+'?v='+version, caption = 'view' )
        else:
            view_link = LoginAreaNavigation(href = page_name, caption = 'view' )
        navigation_links.append(view_link)
        
        logout_link = LoginAreaNavigation(href = '/logout' , caption = self.user.username + '(logout)')
        navigation_links.append(logout_link)
            
        return navigation_links

class LoginAreaNavigation():

    def __init__(self, href, caption):
        self.href = href
        self.caption = caption

class ViewPage(BlogHandler):
    def get(self, page_name):
        version = self.request.get('v','')
        wikiEntity = cached_page_version(page_name, version)
        if not wikiEntity:
            self.redirect('/_edit' + page_name)
        else:
            login_area_links = self.get_login_navigation(page_name)
            self.render('wiki_page.html', login_area_links = login_area_links, e=wikiEntity)
            
    def get_login_navigation(self, page_name):
        navigation_links = list()
        history_link = LoginAreaNavigation(href = '/_history'+page_name, caption = 'history')
        navigation_links.append(history_link)
        version = self.request.get('v','')
        
        if not self.user:        
            login_link = LoginAreaNavigation(href = '/login', caption = 'login')
            navigation_links.append(login_link)
        else:
            if version:
                edit_link = LoginAreaNavigation(href = '/_edit'+page_name+'?v='+version, caption = 'edit' )
            else:
                edit_link = LoginAreaNavigation(href = '/_edit'+page_name, caption = 'edit' )
            navigation_links.append(edit_link)
            
            logout_link = LoginAreaNavigation(href = '/logout' , caption = self.user.username + '(logout)')
            navigation_links.append(logout_link)
            
        return navigation_links

class HistoryPage(BlogHandler):
    def get(self, page_name):
        pages = cached_history_pages(page_name)
        login_area_links = self.get_login_navigation(page_name)
        
        self.render('history_page.html', login_area_links = login_area_links, pages=pages)
    def get_login_navigation(self, page_name):
        navigation_links = list()
        login_link = LoginAreaNavigation(href = page_name, caption = 'view')
        navigation_links.append(login_link)
                
        if not self.user:        
            login_link = LoginAreaNavigation(href = '/login', caption = 'login')
            navigation_links.append(login_link)
        else:
            logout_link = LoginAreaNavigation(href = '/logout' , caption = self.user.username + '(logout)')
            navigation_links.append(logout_link)
            
        return navigation_links

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/welcome', Welcome),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, ViewPage),
                               ],
                              debug=True)

