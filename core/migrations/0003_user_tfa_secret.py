# Generated by Django 4.0.4 on 2022-05-26 16:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_reset'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='tfa_secret',
            field=models.CharField(default='', max_length=255),
        ),
    ]
