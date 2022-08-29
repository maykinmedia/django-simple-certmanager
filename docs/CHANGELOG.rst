=========
Changelog
=========

1.0.0 (2022-08-29)
==================

Initial version of django-simple-certmanager.

This library allows you to manage TLS certificates (and keys) through the Django admin,
in a secure way. Your own code can then include references to the
``simple_certmanager.Certificate`` model.

.. note:: This library is extracted out of the `zgw-consumers`_ library.

Credits to Silvia Amabilino for the initial work and Ewen Le Guilly for splitting it into a
separate package.

.. _zgw-consumers: https://pypi.org/project/zgw-consumers/
