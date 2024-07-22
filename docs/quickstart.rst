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

Generate a Certificate Signing Request (CSR) and a private key in the admin interface.

Generated files are stored at your configured ``PRIVATE_ROOT`` directory.

Download the CSR from the admin interface.

Associate TLS certificates with their CSR.

**Programmatically**

The ``Certificate`` model is the public API of the library.

.. autoclass:: simple_certmanager.models.Certificate
    :members:
    :undoc-members:
    :exclude-members: DoesNotExist, MultipleObjectsReturned, clean, save, id, objects
