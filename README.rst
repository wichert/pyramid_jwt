JWT authentication for Pyramid
==============================

This package implements an authentication policy for Pyramid that using  `JSON
Web Tokens <http://jwt.io/>`_. This standard (`RFC 7519
<https://tools.ietf.org/html/rfc7519>`_) is often used to secure backend APIs.
The excellent `PyJWT <https://pyjwt.readthedocs.org/en/latest/>`_ library is
used for the JWT encoding / decoding logic.

Enabling JWT support in a Pyramid application is very simple:

.. code-block:: python

   from pyramid.config import Configurator
   from pyramid.authorization import ACLAuthorizationPolicy

   def main():
       config = Configurator()
       # Pyramid requires an authorization policy to be active.
       config.set_authorization_policy(ACLAuthorizationPolicy())
       # Enable JWT authentication.
       config.include('pyramid_jwt')
       config.set_jwt_authentication_policy('secret')

This will set a JWT authentication policy using the `Authorization` HTTP header
with a `JWT` scheme to retrieve tokens. Using another HTTP header is trivial:

.. code-block:: python

    config.set_jwt_authentication_policy('secret', http_header='X-My-Header')

If your application needs to decode tokens which contain an `Audience <http://pyjwt.readthedocs.io/en/latest/usage.html?highlight=decode#audience-claim-aud>`_ claim you can extend this with:

.. code-block:: python

    config.set_jwt_authentication_policy('secret',
                                        auth_type='Bearer',
                                        callback=add_role_principals,
                                        audience="example.org")


To make creating valid tokens easier a new ``create_jwt_token`` method is
added to the request. You can use this in your view to create tokens. A simple
authentication view for a REST backend could look something like this:

.. code-block:: python

    @view_config('login', request_method='POST', renderer='json')
    def login(request):
        login = request.POST['login']
        password = request.POST['password']
        user_id = authenticate(login, password)  # You will need to implement this.
        if user_id:
            return {
                'result': 'ok',
                'token': request.create_jwt_token(user_id)
            }
        else:
            return {
                'result': 'error'
            }

Unless you are using JWT cookies within cookies (see the next section), the
standard ``remember()`` and ``forget()`` functions from Pyramid are not useful.
Trying to use them while regular (header-based) JWT authentication is enabled
will result in a warning.

Using JWT inside cookies
------------------------

Optionally, you can use cookies as a transport for the JWT Cookies. This is an
useful technique to allow browser-based web apps to consume your REST APIs
without the hassle of managing token storage (where to store JWT cookies is a
known-issue), since ``http_only`` cookies cannot be handled by Javascript
running on the page

Using JWT within cookies have some added benefits, the first one being *sliding
sessions*: Tokens inside cookies will automatically be reissued whenever
``reissue_time`` is past.

.. code-block:: python

   from pyramid.config import Configurator
   from pyramid.authorization import ACLAuthorizationPolicy

   def main():
       config = Configurator()
       # Pyramid requires an authorization policy to be active.
       config.set_authorization_policy(ACLAuthorizationPolicy())
       # Enable JWT authentication.
       config.include('pyramid_jwt')
       config.set_jwt_cookie_authentication_policy(
           'secret', reissue_time=7200
       )

When working with JWT alone, there's no standard for manually invalidating a
token: Either the token validity expires, or the application needs to handle a
token blacklist (or even better, a whitelist)

On the other hand, when using cookies, this library allows the app to *logout*
a given user by erasing its cookie: This policy follows the standard cookie
deletion mechanism respected by most browsers, so a call to Pyramid's
``forget()`` function will instruct the browser remove that cookie, effectively
throwing that JWT token away, even though it may still be valid.

See `Creating a JWT within a cookie`_ for examples.

Extra claims
------------

Normally pyramid_jwt only makes a single JWT claim: the *subject* (or
``sub`` claim) is set to the principal. You can also add extra claims to the
token by passing keyword parameters to the ``create_jwt_token`` method.

.. code-block:: python

   token = request.create_jwt_token(user.id,
       name=user.name,
       admin=(user.role == 'admin'))


All claims found in a JWT token can be accessed through the ``jwt_claims``
dictionary property on a request. For the above example you can retrieve the
name and admin-status for the user directly from the request:

.. code-block:: python

   print('User id: %d' % request.authenticated_userid)
   print('Users name: %s', request.jwt_claims['name'])
   if request.jwt_claims['admin']:
      print('This user is an admin!')

Keep in mind that data ``jwt_claims`` only reflects the claims from a JWT
token and do not check if the user is valid: the callback configured for the
authentication policy is *not* checked. For this reason you should always use
``request.authenticated_userid`` instead of ``request.jwt_claims['sub']``.

You can also use extra claims to manage extra principals for users. For example
you could claims to represent add group membership or roles for a user. This
requires two steps: first add the extra claims to the JWT token as shown above,
and then use the authentication policy's callback hook to turn the extra claim
into principals. Here is a quick example:

.. code-block:: python

   def add_role_principals(userid, request):
      return ['role:%s' % role for role in request.jwt_claims.get('roles', [])]

   config.set_jwt_authentication_policy(callback=add_role_principals)


You can then use the role principals in an ACL:

.. code-block:: python

   class MyView:
       __acl__ = [
           (Allow, Everyone, ['read']),
           (Allow, 'role:admin', ['create', 'update']),
       ]

Validation Example
------------------

After creating and returning the token through your API with
``create_jwt_token`` you can test by issuing an HTTP authorization header type
for JWT.

.. code-block:: text

   GET /resource HTTP/1.1
   Host: server.example.com
   Authorization: JWT eyJhbGciOiJIUzI1NiIXVCJ9...TJVA95OrM7E20RMHrHDcEfxjoYZgeFONFh7HgQ

We can test using curl.

.. code-block:: bash

   curl --header 'Authorization: JWT TOKEN' server.example.com/ROUTE_PATH

.. code-block:: python

   config.add_route('example', '/ROUTE_PATH')
   @view_config(route_name=example)
   def some_action(request):
       if request.authenticated_userid:
           # Do something


Settings
--------

There are a number of flags that specify how tokens are created and verified.
You can either set this in your .ini-file, or pass/override them directly to the
``config.set_jwt_authentication_policy()`` function.

+--------------+-----------------+---------------+--------------------------------------------+
| Parameter    | ini-file entry  | Default       | Description                                |
+==============+=================+===============+============================================+
| private_key  | jwt.private_key |               | Key used to hash or sign tokens.           |
+--------------+-----------------+---------------+--------------------------------------------+
| public_key   | jwt.public_key  |               | Key used to verify token signatures. Only  |
|              |                 |               | used with asymmetric algorithms.           |
+--------------+-----------------+---------------+--------------------------------------------+
| algorithm    | jwt.algorithm   | HS512         | Hash or encryption algorithm               |
+--------------+-----------------+---------------+--------------------------------------------+
| expiration   | jwt.expiration  |               | Number of seconds (or a datetime.timedelta |
|              |                 |               | instance) before a token expires.          |
+--------------+-----------------+---------------+--------------------------------------------+
| audience     | jwt.audience    |               | Proposed audience for the token            |
+--------------+-----------------+---------------+--------------------------------------------+
| leeway       | jwt.leeway      | 0             | Number of seconds a token is allowed to be |
|              |                 |               | expired before it is rejected.             |
+--------------+-----------------+---------------+--------------------------------------------+
| http_header  | jwt.http_header | Authorization | HTTP header used for tokens                |
+--------------+-----------------+---------------+--------------------------------------------+
| auth_type    | jwt.auth_type   | JWT           | Authentication type used in Authorization  |
|              |                 |               | header. Unused for other HTTP headers.     |
+--------------+-----------------+---------------+--------------------------------------------+
| json_encoder |                 | None          | A subclass of JSONEncoder to be used       |
|              |                 |               | to encode principal and claims infos.      |
+--------------+-----------------+---------------+--------------------------------------------+

The follow options applies to the cookie-based authentication policy:

+----------------+---------------------------+---------------+--------------------------------------------+
| Parameter      | ini-file entry            | Default       | Description                                |
+================+===========================+===============+============================================+
| cookie_name    | jwt.cookie_name           | Authorization | Key used to identify the cookie.           |
+----------------+---------------------------+---------------+--------------------------------------------+
| cookie_path    | jwt.cookie_path           | None          | Path for cookie.                           |
+----------------+---------------------------+---------------+--------------------------------------------+
| https_only     | jwt.https_only_cookie     | True          | Whether or not the token should only be    |
|                |                           |               | sent through a secure HTTPS transport      |
+----------------+---------------------------+---------------+--------------------------------------------+
| samesite       | jwt.samesite              | one           | Set the 'SameSite' attribute of the cookie |
|                |                           |               | can be 'strict', 'lax', 'none'             |
+----------------+---------------------------+---------------+--------------------------------------------+
| reissue_time   | jwt.cookie_reissue_time   |  None         | Number of seconds (or a datetime.timedelta |
|                |                           |               | instance) before a cookie (and the token   |
|                |                           |               | within it) is reissued                     |
+----------------+---------------------------+---------------+--------------------------------------------+

Pyramid JWT example use cases
=============================

This is a basic guide (that will assume for all following statements that you
have followed the Readme for this project) that will explain how (and why) to
use JWT to secure/restrict access to a pyramid REST style backend API, this
guide will explain a basic overview on:

- Creating JWT's
- Decoding JWT's
- Restricting access to certain pyramid views via JWT's


Creating JWT's
--------------

First off, lets start with the first view in our pyramid project, this would
normally be say a login view, this view has no permissions associated with it,
any user can access and post login credentials to it, for example:

.. code-block:: python

   def authenticate_user(login, password):
       # Note the below will not work, its just an example of returning a user
       # object back to the JWT creation.
       login_query = session.query(User).\
           filter(User.login == login).\
           filter(User.password == password).first()

       if login_query:
           user_dict = {
               'userid': login_query.id,
               'user_name': login_query.user_name,
               'roles': login_query.roles
           }
           # An example of login_query.roles would be a list
           # print(login_query.roles)
           # ['admin', 'reports']
           return user_dict
       else:
           # If we end up here, no logins have been found
           return None

   @view_config('login', request_method='POST', renderer='json')
   def login(request):
       '''Create a login view
       '''
       login = request.POST['login']
       password = request.POST['password']
       user = authenticate(login, password)
       if user:
           return {
               'result': 'ok',
               'token': request.create_jwt_token(
                                               user['userid'],
                                               roles=user['roles'],
                                               userName=user['user_name']
                                               )
           }
       else:
           return {
               'result': 'error',
               'token': None
           }

Now what this does is return your JWT back to whatever front end application
you may have, with the user details, along with their permissions, this will
return a decoded token such as:

.. code-block::

   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6Imx1a2UiLCJyb2xlcyI6WyJhZG1pbiIsInJlcG9ydHMiXSwic3ViIjo0LCJpYXQiOjE1MTkwNDQyNzB9.__KjyW1U-tpAEvTbSJsasS-8CaFyXH784joUPONH6hQ

Now I would suggest heading over to `JWT.io <https://jwt.io>`_, copy this data
into their page, and you will see the decoded token:

.. code-block:: json

   {
     "userName": "luke",
     "roles": [
       "admin",
       "reports"
     ],
     "sub": 4,
     "iat": 1519044270
   }

Note, at the bottom of jwt.io's webpage, that the signature shows verified, if
you change the "secret" at the bottom, it will say "NOT Verified" this is
because in order for any JWT process to be verified, the valid "secret" or
"private key" must be used. It is important to note that any data sent in a JWT
is accessible and readable by anyone.

Decoding JWT
------------

The following section would also work if pyramid did not create the JWT, all it
needs to know to decode a JWT is the "secret" or "private key" used to
create/sign the original JWT.By their nature  JWT's aren't secure, but they can
be used "to secure". In our example above, we returned the "roles" array in our
JWT, this had two properties "admin" and "reports" so we could then in our
pyramid application, setup an ACL to map JWT permissions to pyramid based
security, for example in our projects __init__.py we could add:

.. code-block:: python

   from pyramid.security import ALL_PERMISSIONS

   class RootACL(object):
       __acl__ = [
           (Allow, 'admin', ALL_PERMISSIONS),
           (Allow, 'reports', ['reports'])
       ]

       def __init__(self, request):
           pass

What this ACL will do is allow anyone with the "admin" role in their JWT access
to all views protected via a permission, where as users with "reports" in their
JWT will only have access to views protected via the "reports" permission.

Now this ACL in itself is not enough to map the JWT permission to pyramids
security backend, we need to also add the following to __init__.py:

.. code-block:: python

   from pyramid.authorization import ACLAuthorizationPolicy


   def add_role_principals(userid, request):
       return request.jwt_claims.get('roles', [])

   def main(global_config, **settings):
       """ This function returns a Pyramid WSGI application.
       """
       config = Configurator(settings=settings)
       ...
       # Enable JWT - JSON Web Token based authentication
       config.set_root_factory(RootACL)
       config.set_authorization_policy(ACLAuthorizationPolicy())
       config.include('pyramid_jwt')
       config.set_jwt_authentication_policy('myJWTsecretKeepThisSafe',
                                           auth_type='Bearer',
                                           callback=add_role_principals)

This code will map any properties of the "roles" attribute of the JWT, run them
through the ACL and then tie them into pyramids security framework.

Creating a JWT within a cookie
------------------------------

Since cookie-based authentication is already standardized within Pyramid by the
``remember()`` and ``forget()`` calls, you should simply use them:

.. code-block:: python

   from pyramid.response import Response
   from pyramid.security import remember

   @view_config('login', request_method='POST', renderer='json')
   def login_with_cookies(request):
       '''Create a login view
       '''
       login = request.POST['login']
       password = request.POST['password']
       user = authenticate(login, password)  # From the previous snippet
       if user:
           headers = remember(
               user['userid'],
               roles=user['roles'],
               userName=user['user_name']
           )
           return Response(headers=headers, body="OK")  # Or maybe redirect somewhere else
       return Response(status=403)  # Or redirect back to login

Please note that since the JWT cookies will be stored inside the cookies,
there's no need for your app to explicitly include it on the response body.
The browser (or whatever consuming this response) is responsible to keep that
cookie for as long as it's valid, and re-send it on the following requests.

Also note that there's no need to decode the cookie manually. The Policy
handles that through the existing ``request.jwt_claims``.

How is this secure?
-------------------

For example, a JWT could easily be manipulated, anyone could hijack the token,
change the values of the "roles" array to gain access to a view they do not
actually have access to. WRONG! pyramid_jwt checks the signature of all JWT
tokens as part of the decode process, if it notices that the signature of the
token is not as expected, it means either the application has been setup
correctly with the wrong private key, OR an attacker has tried to manipulate
the token.

The major security concern when working with JWT tokens is where to store the
token itself: While pyramid_jwt is able to detect tampered tokens, nothing can
be done if the actual valid token leaks. Any user with a valid token will be
correctly authenticated within your app. Storing the token securely is outside
the scope of this library.

When using JWT within a cookie, the browser (or tool consuming the cookie) is
responsible for storing it, but pyramid_jwt does set the ``http_only`` flag on
all cookies, so javascript running on the page cannot access these cookies,
which helps mitigate XSS attacks. It's still mentioning that the tokens are
still visible through the browser's debugging/inspection tools.

Securing views with JWT's
-------------------------

In the example posted above we creating an "admin" role that we gave
ALL_PERMISSIONS access in our ACL, so any user with this role could access any
view e.g.:

.. code-block:: python

   @view_config(route_name='view_a', request_method='GET',
                permission="admin", renderer='json')
   def view_a(request):
       return

   @view_config(route_name='view_b', request_method='GET',
                permission="cpanel", renderer='json')
   def view_b(request):
       return

This user would be able to access both of these views, however any user with
the "reports" permission would not be able to access any of these views, they
could only access permissions with "reports". Obviously in our use case, one
user had both "admin" and "reports" permissions, so they would be able to
access any view regardless.

