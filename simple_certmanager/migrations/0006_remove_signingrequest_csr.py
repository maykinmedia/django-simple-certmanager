# Generated by Django 4.2.14 on 2024-08-12 14:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        (
            "simple_certmanager",
            "0005_remove_signingrequest_csr_and_private_key_must_be_set_together",
        ),
    ]

    operations = [
        migrations.RemoveField(
            model_name="signingrequest",
            name="csr",
        ),
    ]
