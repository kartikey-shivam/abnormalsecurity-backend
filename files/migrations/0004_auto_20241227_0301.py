# Generated by Django 2.2.28 on 2024-12-26 21:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0003_auto_20241225_0144'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='encryptedfile',
            name='encryption_key',
        ),
        migrations.AlterField(
            model_name='encryptedfile',
            name='file',
            field=models.FileField(upload_to='uploads/%Y/%m/%d/'),
        ),
    ]
