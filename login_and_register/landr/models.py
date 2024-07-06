from django.db import models

class masters(models.Model):
    master_id = models.AutoField(primary_key=True)
    master_name = models.CharField(max_length=50)
    password = models.CharField(max_length=20)

    class Meta:
        db_table = 'masters'

    def __str__(self):
        return self.master_name

class User(models.Model):
    username = models.CharField(max_length=50, primary_key=True)
    password = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    designation = models.CharField(max_length=50)

    class Meta:
        db_table = 'users'

    def __str__(self):
        return self.username

class IpTable(models.Model):
    username = models.CharField(max_length=50)
    ip_address = models.CharField(max_length=32,primary_key=True)

    class Meta:
        db_table = 'ip_table'

    def __str__(self):
        return f"{self.username} - {self.ip_address}"


