Changelog
=========

1.4 - August 9, 2018
--------------------

- `Pull request #21 <https://github.com/wichert/pyramid_jwt/pull/21>`_:
  add support for JWT aud claims, from `Luke Crooks
  <https://github.com/crooksey>`_.

1.3 - March 20, 2018
---------------------

- `Issue #20 <https://github.com/wichert/pyramid_jwt/issues/20>`_:
  Fix handling of public keys.
- `Pull request #17 <https://github.com/wichert/pyramid_jwt/pull/17>`_:
  a lot of documentation improvements from `Luke Crooks
  <https://github.com/crooksey>`_.


1.2 - May 25, 2017
------------------

- Fix a `log.warn` deprecation warning on Python 3.6.

- Documentation improvements, courtesy of `Éric Araujo <https://github.com/merwok>`_
  and `Guillermo Cruz <https://github.com/webjunkie01>`_.

- `Pull request #10 <https://github.com/wichert/pyramid_jwt/pull/10>`_
  Allow use of a custom JSON encoder.
  Submitted by `Julien Meyer <https://github.com/julienmeyer>`_.


1.1 - May 4, 2016
-----------------

- `Issue #2 <https://github.com/wichert/pyramid_jwt/issues/2>`_:
  Support setting and reading extra claims in a JWT token.

- `Pull request #4 <https://github.com/wichert/pyramid_jwt/pull/4>`_:
  Fix parsing of expiration and leeway settings from a configuration value.
  Submitted by `Daniel Kraus <https://github.com/dakra>`_.

- `Pull request #3 <https://github.com/wichert/pyramid_jwt/pull/3>`_:
  Allow overriding the expiration timestamp for a token when creating a new
  token. Submitted by `Daniel Kraus`_.


1.0 - December 17, 2015
-----------------------

- First release
