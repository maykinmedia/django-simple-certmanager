Quickstart
==========

Installation
------------

**Requirements**

* Python 3.7 or newer
* Django 3.2+

1. Install from PyPI using ``pip``:

   .. code-block:: bash

      pip install django-simple-certmanager

2. Add ``simple_certmanager`` to the ``INSTALLED_APPS`` setting.
3. Run ``python src/manage.py migrate`` to create the necessary database tables
4. Configure `django-privates <https://django-privates.readthedocs.io/en/latest/quickstart.html>`_
   correctly - the TLS certificates and keys are stored outside of ``settings.MEDIA_ROOT``
   for security reasons.


Usage
-----

In the Django admin, you can create:

* ``Certificate`` instances to (re-)use (mutual) TLS configuration
