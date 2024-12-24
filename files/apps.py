from django.apps import AppConfig

class FilesConfig(AppConfig):
    name = 'files'
    verbose_name = 'File Management'

    def ready(self):
        pass  # Add any startup code here if needed 