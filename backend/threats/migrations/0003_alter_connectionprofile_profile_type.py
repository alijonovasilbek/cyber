from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('threats', '0002_connectionprofile_scansession'),
    ]

    operations = [
        migrations.AlterField(
            model_name='connectionprofile',
            name='profile_type',
            field=models.CharField(choices=[('ssh', 'SSH'), ('telnet', 'Telnet'), ('snmp', 'SNMP')], max_length=20),
        ),
    ]
