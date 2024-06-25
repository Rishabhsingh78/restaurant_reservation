from django.contrib import admin
from .models import User,Slot,Reservation
admin.site.register(User)
admin.site.register(Reservation)
admin.site.register(Slot)