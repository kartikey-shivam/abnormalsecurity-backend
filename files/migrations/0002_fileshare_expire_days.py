# Generated by Django 2.2.28 on 2024-12-24 08:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='fileshare',
            name='expire_days',
            field=models.IntegerField(default=7),
        ),
    ]