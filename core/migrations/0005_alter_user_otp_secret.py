# Generated by Django 5.0.7 on 2024-09-12 04:34

import pyotp
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_user_otp_secret"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="otp_secret",
            field=models.CharField(
                blank=True, default=pyotp.random_base32, max_length=32, null=True
            ),
        ),
    ]