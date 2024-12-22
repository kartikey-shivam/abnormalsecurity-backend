from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.utils import timezone
from datetime import timedelta
from .models import EncryptedFile, FileShare
from .utils import handle_uploaded_file, decrypt_file
from .forms import FileUploadForm, FileShareForm

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            encrypted_file = handle_uploaded_file(uploaded_file, request.user)
            return redirect('file_detail', pk=encrypted_file.pk)
    else:
        form = FileUploadForm()
    return render(request, 'files/upload.html', {'form': form})

@login_required
def file_list(request):
    user_files = EncryptedFile.objects.filter(uploaded_by=request.user)
    shared_files = FileShare.objects.filter(
        shared_with=request.user,
        expires_at__gt=timezone.now()
    )
    return render(request, 'files/file_list.html', {
        'user_files': user_files,
        'shared_files': shared_files
    })

@login_required
def file_detail(request, pk):
    file = get_object_or_404(EncryptedFile, pk=pk)
    if file.uploaded_by != request.user:
        share = get_object_or_404(FileShare, 
            file=file, 
            shared_with=request.user,
            expires_at__gt=timezone.now()
        )
    
    if request.method == 'POST':
        form = FileShareForm(request.POST)
        if form.is_valid():
            share = form.save(commit=False)
            share.file = file
            share.shared_by = request.user
            share.expires_at = timezone.now() + timedelta(days=form.cleaned_data['expire_days'])
            share.save()
            return redirect('file_detail', pk=pk)
    else:
        form = FileShareForm()
        
    return render(request, 'files/file_detail.html', {
        'file': file,
        'form': form
    })

@login_required
def download_file(request, pk):
    file = get_object_or_404(EncryptedFile, pk=pk)
    
    # Check permissions
    if file.uploaded_by != request.user:
        share = get_object_or_404(FileShare, 
            file=file, 
            shared_with=request.user,
            permission='download',
            expires_at__gt=timezone.now()
        )
    
    # Decrypt and serve file
    with file.file.open('rb') as f:
        encrypted_content = f.read()
    
    decrypted_content = decrypt_file(encrypted_content, file.encryption_key)
    
    response = HttpResponse(decrypted_content, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="{}"'.format(file.original_filename)
    return response

def shared_file_access(request, uuid):
    share = get_object_or_404(FileShare, share_link=uuid, expires_at__gt=timezone.now())
    
    if request.method == 'POST' and share.permission == 'download':
        return download_file(request, share.file.pk)
        
    return render(request, 'files/shared_file.html', {'share': share}) 