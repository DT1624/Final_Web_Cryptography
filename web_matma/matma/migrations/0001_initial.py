# Generated by Django 3.1.12 on 2024-11-18 11:24

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RSAKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('p', models.IntegerField()),
                ('q', models.IntegerField()),
                ('e', models.IntegerField()),
                ('n', models.TextField()),
            ],
        ),
    ]