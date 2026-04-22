from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('threats', '0003_alter_connectionprofile_profile_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='connectionprofile',
            name='profile_type',
            field=models.CharField(
                choices=[('ssh', 'SSH'), ('telnet', 'Telnet'), ('snmp', 'SNMP'), ('web', 'Web')],
                max_length=20,
            ),
        ),
    ]
