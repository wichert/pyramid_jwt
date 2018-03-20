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

How is this secure?
-------------------

For example, a JWT could easily be manipulated, anyone could hijack the token,
change the values of the "roles" array to gain access to a view they do not
actually have access to. WRONG! pyramid_jwt checks the signature of all JWT
tokens as part of the decode process, if it notices that the signature of the
token is not as expected, it means either the application has been setup
correctly with the wrong private key, OR an attacker has tried to manipulate
the token.

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

