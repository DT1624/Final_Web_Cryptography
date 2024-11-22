# Generated by Django 4.2.3 on 2024-11-19 17:11

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('matma', '0002_delete_rsakey'),
    ]

    operations = [
        migrations.CreateModel(
            name='RSAKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('p', models.TextField()),
                ('q', models.TextField()),
                ('e', models.TextField()),
                ('n', models.TextField(editable=False)),
                ('phi', models.TextField(editable=False)),
                ('d_prv', models.TextField(editable=False)),
            ],
        ),
    ]