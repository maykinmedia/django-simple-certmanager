Quickstart
==========

Requirements
------------

* Python 3.10 or newer
* Django 3.2 or newer

Installation
------------

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

**Django admin**

In the Django admin, you can create ``Certificate`` instances to (re-)use (mutual) TLS
configuration.

Whenever an instance is deleted (through the admin or code), the associated files are
purged as well.

You can create and download ``Certificate Signing Requests`` (CSR) through the
admin as well.

Upload the TLS certificate from the Certificate Authority (CA) to the 
``Certificate Signing Request`` instance to verify it and store it in the database.

The ``Certificate`` instance will then contain the certificate and the private key if valid.

**Programmatically**

The ``Certificate`` model is the public API of the library.

.. autoclass:: simple_certmanager.models.Certificate
    :members:
    :undoc-members:
    :exclude-members: DoesNotExist, MultipleObjectsReturned, clean, save, id, objects
