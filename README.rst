JWT authentication for Pyramid
==============================

This package implements an authentication policy for Pyramid that using  `JSON
Web Tokens <http://jwt.io/>`_. This standard (`RFC 7519
<https://tools.ietf.org/html/rfc7519>`_) is often used to secure backens APIs.

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

::

    config.set_jwt_authentication_policy('secret', http_header='X-My-Header')

To make creating valid tokens easier a new ``create_jwt_token`` method is
added to the request. You can use this in your view to create tokens. A simple
authentication view for a REST backend could look something like this:

.. code-block:: python

    @view_config('login', request_method='POST', renderer='json')
    def login(request):
        login = request.POST['login']
        password = request.POST['password']
        user_id = authenticate(login, password)
        if user_id:
            return {
                'result': 'ok',
                'token': request.create_jwt_token(user_id)
            }
        else:
            return {
                'result': 'error'
            }

Since JWT is typically used via HTTP headers and does not use cookies the
standard ``remember()`` and ``forget()`` functions from Pyramid are not useful.
Trying to use them while JWT authentication is enabled will result in a warning.
