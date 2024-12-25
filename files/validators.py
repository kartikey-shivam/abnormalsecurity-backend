from django.core.exceptions import ValidationError
import magic

def validate_file_type(file):
    allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
    file_type = magic.from_buffer(file.read(1024), mime=True)
    if file_type not in allowed_types:
        raise ValidationError('Unsupported file type: {}'.format(file_type)) 