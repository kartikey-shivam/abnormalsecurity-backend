from django import forms
from .models import FileShare

class FileUploadForm(forms.Form):
    file = forms.FileField()

class FileShareForm(forms.ModelForm):
    expire_days = forms.IntegerField(min_value=1, max_value=30, initial=7)
    
    class Meta:
        model = FileShare
        fields = ['shared_with', 'permission'] 