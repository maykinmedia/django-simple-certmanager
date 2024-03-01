.. simple_certmanager documentation master file, created by startproject.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to simple_certmanager's documentation!
=================================================

|build-status| |code-quality| |black| |coverage| |docs|

|python-versions| |django-versions| |pypi-version|

Manage TLS certificates and keys in the Django admin

Features
========

* Manage (mutual) TLS certificates
* Certificate introspection and validation
* Certificate/key files stored in private media
* Certificate/key files deleted when the database record is deleted

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   commands


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. |build-status| image:: https://github.com/maykinmedia/django-simple-certmanager/workflows/Run%20CI/badge.svg
    :alt: Build status
    :target: https://github.com/maykinmedia/django-simple-certmanager/actions?query=workflow%3A%22Run+CI%22

.. |code-quality| image:: https://github.com/maykinmedia/django-simple-certmanager/workflows/Code%20quality%20checks/badge.svg
     :alt: Code quality checks
     :target: https://github.com/maykinmedia/django-simple-certmanager/actions?query=workflow%3A%22Code+quality+checks%22

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. |coverage| image:: https://codecov.io/gh/maykinmedia/django-simple-certmanager/branch/main/graph/badge.svg
    :target: https://codecov.io/gh/maykinmedia/django-simple-certmanager
    :alt: Coverage status

.. |docs| image:: https://readthedocs.org/projects/django-simple-certmanager/badge/?version=latest
    :target: https://django-simple-certmanager.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/django-simple-certmanager.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/django-simple-certmanager.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/django-simple-certmanager.svg
    :target: https://pypi.org/project/django-simple-certmanager/
