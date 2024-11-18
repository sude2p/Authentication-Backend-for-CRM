# Generated by Django 5.0.7 on 2024-08-06 05:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organization', '0006_alter_organization_contact_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='organization',
            name='city',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='organization',
            name='country',
            field=models.CharField(default='', max_length=200),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='organization',
            name='descripton',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='organization',
            name='postal_code',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='organization',
            name='province',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='organization',
            name='street',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='organization',
            name='website',
            field=models.URLField(blank=True, null=True),
        ),
    ]
