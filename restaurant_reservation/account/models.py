from django.db import models
from django.contrib.auth.models import AbstractUser
from django.forms import ValidationError
from django.db.models import Q


class User(AbstractUser):  # yaha pe AbstractUser hm inherate kr rhe hai isme default field aajati utill hme koi need na ho 
    USERNAME_FIELD = 'username'


class Slot(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    table_number = models.PositiveIntegerField()
    location = models.CharField(max_length=100)
    class Meta:
        unique_together = ('date', 'start_time', 'end_time', 'location', 'table_number')
    
    def __str__(self):
        return f"Slot id:{self.id} on {self.date} from {self.start_time} to {self.end_time} at {self.location}"
    

class Reservation(models.Model):
    slot = models.ForeignKey(Slot,on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=10)
    guests = models.PositiveIntegerField()

    def __str__(self):
        return f"Reservation for {self.name} on {self.slot.date} at Table {self.slot.table_number} - {self.slot.location}"
    

    def clean(self):
        # Check for overlapping reservations for the same table and slot time
        if Reservation.objects.filter(
            Q(slot=self.slot) &
            Q(slot__start_time__lt=self.slot.end_time) &
            Q(slot__end_time__gt=self.slot.start_time)
        ).exclude(id=self.id).exists():
            raise ValidationError('This table is already booked during this time slot.')   