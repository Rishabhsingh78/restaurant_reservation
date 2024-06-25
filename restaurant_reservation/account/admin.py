from django.contrib import admin
from .models import User,Slot,Reservation
admin.site.register(User)
admin.site.register(Reservation)
# admin.site.register(Slot)

@admin.register(Slot)
class SlotAdmin(admin.ModelAdmin):
    list_display = ('id', 'date', 'start_time', 'end_time', 'location', 'table_number')
    list_filter = ('date', 'location', 'table_number')
    search_fields = ('location', 'table_number')