from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):  # yaha pe AbstractUser hm inherate kr rhe hai isme default field aajati utill hme koi need na ho 
    USERNAME_FIELD = 'username'


class Slot(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    location = models.CharField(max_length=100)
    
    def __str__(self):
        return f"Slot id:{self.id} on {self.date} from {self.start_time} to {self.end_time} at {self.location}"