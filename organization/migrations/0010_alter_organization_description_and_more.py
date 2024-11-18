# Generated by Django 5.0.7 on 2024-08-20 12:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organization", "0009_remove_organization_logo"),
    ]

    operations = [
        migrations.AlterField(
            model_name="organization",
            name="description",
            field=models.TextField(blank=True, default=""),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="organization",
            name="organization_type",
            field=models.CharField(blank=True, default="", max_length=200),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="organization",
            name="province",
            field=models.CharField(blank=True, default="", max_length=200),
            preserve_default=False,
        ),
    ]
