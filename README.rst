

Welcome to django-simple-certmanager's documentation!
=================================================

:Version: 0.1.0
:Source: https://github.com/maykinmedia/django-simple-certmanager
:Keywords: certificates
:PythonVersion: 3.9

|build-status| |code-quality| |black| |coverage| |docs|

|python-versions| |django-versions| |pypi-version|

Managing TLS certificates

.. contents::

.. section-numbering::

Features
========

* Manage (mutual) TLS certificates

Installation
============

Requirements
------------

* Python 3.7 or above
* setuptools 30.3.0 or above
* Django 2.2 or newer


Install
-------

1. Install from PyPI

.. code-block:: bash

    pip install django-simple-certmanager

2. Add ``simple_certmanager`` to the ``INSTALLED_APPS`` setting.

3. Run the migrations

.. code-block:: bash

    python manage.py migrate

.. code-block:: bash
    python src/manage.py migrate


.. |build-status| image:: https://github.com/maykinmedia/django-simple-certmanager/workflows/Run%20CI/badge.svg
    :alt: Build status
    :target: https://github.com/maykinmedia/django-simple-certmanager/actions?query=workflow%3A%22Run+CI%22

.. |code-quality| image:: https://github.com/maykinmedia/django-simple-certmanager/workflows/Code%20quality%20checks/badge.svg
     :alt: Code quality checks
     :target: https://github.com/maykinmedia/django-simple-certmanager/actions?query=workflow%3A%22Code+quality+checks%22

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. |coverage| image:: https://codecov.io/gh/maykinmedia/django-simple-certmanager/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/maykinmedia/django-simple-certmanager
    :alt: Coverage status

.. |docs| image:: https://readthedocs.org/projects/django-simple-certmanager/badge/?version=latest
    :target: https://django-simple-certmanager.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/django-simple-certmanager.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/django-simple-certmanager.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/django-simple-certmanager.svg
    :target: https://pypi.org/project/django-simple-certmanager/
